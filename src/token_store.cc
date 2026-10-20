// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "token_store.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <json/json.h>
#include <libgen.h>
#include <sasl/sasl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <vector>

#include "config.h"
#include "http.h"
#include "log.h"

namespace sasl_xoauth2 {

namespace {

constexpr int kMaxRefreshAttempts = 2;

// Long enough for another process to finish a token request (see the HTTP
// timeouts in http.cc), short enough not to stall delivery indefinitely.
constexpr int kLockTimeoutMs = 45 * 1000;
constexpr int kLockPollMs = 100;

std::string GetTempSuffix() {
  timeval t = {};
  gettimeofday(&t, nullptr);
  const uint64_t time_ms = static_cast<uint64_t>(t.tv_sec) * 1000 +
                           static_cast<uint64_t>(t.tv_usec) / 1000;

  char buf[128];
  snprintf(buf, sizeof(buf), "%d.%" PRIu64, static_cast<int>(getpid()),
           time_ms);

  return std::string(buf);
}

void ReadOverride(const Json::Value &root, const std::string &key,
                  std::optional<std::string> *output) {
  if (root.isMember(key)) {
    *output = root[key].asString();
  }
}

void WriteOverride(const std::string &key,
                   const std::optional<std::string> &value,
                   Json::Value *output) {
  if (value) {
    (*output)[key] = *value;
  }
}

// Exclusive advisory lock on a separate lock file. (The token file itself
// cannot be locked: it is replaced by rename() on every update.) Released when
// the object goes out of scope.
class FileLock {
 public:
  FileLock() = default;
  ~FileLock() {
    if (fd_ >= 0) close(fd_);
  }

  FileLock(const FileLock &) = delete;
  FileLock &operator=(const FileLock &) = delete;

  bool Acquire(Log *log, const std::string &path) {
    fd_ = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd_ < 0) {
      log->Write("FileLock: unable to open %s: %s", path.c_str(),
                 strerror(errno));
      return false;
    }
    for (int waited_ms = 0;; waited_ms += kLockPollMs) {
      if (flock(fd_, LOCK_EX | LOCK_NB) == 0) return true;
      if (errno != EWOULDBLOCK && errno != EINTR) {
        log->Write("FileLock: flock failed on %s: %s", path.c_str(),
                   strerror(errno));
        break;
      }
      if (waited_ms >= kLockTimeoutMs) {
        log->Write("FileLock: timed out waiting for %s", path.c_str());
        break;
      }
      usleep(kLockPollMs * 1000);
    }
    close(fd_);
    fd_ = -1;
    return false;
  }

 private:
  int fd_ = -1;
};

bool WriteAll(int fd, const std::string &data) {
  const char *next = data.data();
  size_t remaining = data.size();
  while (remaining > 0) {
    const ssize_t written = write(fd, next, remaining);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    next += written;
    remaining -= static_cast<size_t>(written);
  }
  return true;
}

void SyncParentDirectory(const std::string &path) {
  std::vector<char> buf(path.begin(), path.end());
  buf.push_back('\0');
  const int fd = open(dirname(buf.data()), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return;
  fsync(fd);
  close(fd);
}

// Replaces |path| with |contents| such that readers see either the old or the
// new file, never a partial one, and a failure (e.g. a full disk) leaves the
// old file untouched. The file holds secrets, so it is never made readable by
// anyone beyond the owner and group of the file it replaces.
int WriteFileAtomically(Log *log, const std::string &path,
                        const std::string &contents) {
  struct stat existing = {};
  const bool have_existing = (stat(path.c_str(), &existing) == 0);
  const mode_t mode =
      have_existing
          ? ((existing.st_mode & (S_IRWXU | S_IRWXG)) | S_IRUSR | S_IWUSR)
          : (S_IRUSR | S_IWUSR);

  const std::string temp_path = path + "." + GetTempSuffix();
  // O_EXCL | O_NOFOLLOW: never write through a file or symlink planted at the
  // temporary path.
  const int fd =
      open(temp_path.c_str(),
           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
  if (fd < 0) {
    log->Write("TokenStore::Write: failed to open file %s for writing: %s",
               temp_path.c_str(), strerror(errno));
    return SASL_FAIL;
  }

  // The umask can only have removed bits from |mode|, so a failure here never
  // leaves the file more permissive; restore the intended mode and group (so
  // that a group-readable token file stays readable).
  if (fchmod(fd, mode) != 0) {
    log->Write("TokenStore::Write: unable to set mode of %s: %s",
               temp_path.c_str(), strerror(errno));
  }
  if (have_existing && existing.st_gid != getegid() &&
      fchown(fd, static_cast<uid_t>(-1), existing.st_gid) != 0) {
    log->Write("TokenStore::Write: unable to keep group of %s: %s",
               path.c_str(), strerror(errno));
  }
  bool ok = WriteAll(fd, contents) && fsync(fd) == 0;
  int saved_errno = errno;
  if (close(fd) != 0 && ok) {
    ok = false;
    saved_errno = errno;
  }

  if (!ok) {
    log->Write("TokenStore::Write: failed to write %s: %s", temp_path.c_str(),
               strerror(saved_errno));
    unlink(temp_path.c_str());
    return SASL_FAIL;
  }

  if (rename(temp_path.c_str(), path.c_str()) != 0) {
    log->Write("TokenStore::Write: rename failed with %s", strerror(errno));
    unlink(temp_path.c_str());
    return SASL_FAIL;
  }

  // Make the rename itself durable, so a crash cannot bring back a refresh
  // token the provider has already rotated out.
  SyncParentDirectory(path);
  return SASL_OK;
}

// Explains the provider's error code (RFC 6749, section 5.2) in terms of what
// to do about it. Microsoft adds an AADSTS code to error_description.
const char *HintForTokenError(const std::string &error) {
  if (error == "invalid_grant")
    return "the refresh token was rejected (expired, revoked, or issued for a "
           "different client/tenant/scope); obtain a new one with "
           "'sasl-xoauth2-tool get-token'";
  if (error == "invalid_client")
    return "the client was rejected; check client_id and client_secret (an "
           "Entra ID client secret may have expired; public clients must use "
           "an empty client_secret)";
  if (error == "unauthorized_client")
    return "the client is unknown in this tenant or may not use this grant "
           "type; check client_id, the tenant in token_endpoint, admin "
           "consent, and the app registration (e.g. 'Allow public client "
           "flows' for device flow)";
  if (error == "invalid_scope")
    return "the requested scope is not valid for this client; check scope";
  return nullptr;
}

void LogTokenError(Log *log, const std::string &response) {
  try {
    std::stringstream ss(response);
    Json::Value root;
    ss >> root;
    if (!root.isObject() || !root.isMember("error")) return;
    const std::string error = root["error"].asString();
    log->Write("TokenStore::Refresh: error=%s, description=%s", error.c_str(),
               root.get("error_description", "").asString().c_str());
    const char *hint = HintForTokenError(error);
    if (hint) log->Write("TokenStore::Refresh: hint: %s", hint);
  } catch (const std::exception &) {
    // Not JSON; the raw response has already been logged.
  }
}

}  // namespace

/* static */ std::unique_ptr<TokenStore> TokenStore::Create(
    Log *log, const std::string &path, bool enable_updates) {
  std::unique_ptr<TokenStore> store(new TokenStore(log, path, enable_updates));
  if (store->Read() != SASL_OK) return {};
  return store;
}

int TokenStore::RefreshWindow() const {
  return override_refresh_window_.value_or(Config::Get()->refresh_window());
}

std::string TokenStore::GrantType() const {
  return override_grant_type_.value_or(Config::Get()->grant_type());
}

bool TokenStore::NeedsRefresh() const {
  return access_.empty() || (time(nullptr) + RefreshWindow()) >= expiry_;
}

int TokenStore::GetAccessToken(std::string *token) {
  if (NeedsRefresh()) {
    log_->Write("TokenStore::GetAccessToken: token expired. refreshing.");
    int err = Refresh();
    if (err != SASL_OK) return err;
  }

  *token = access_;
  return SASL_OK;
}

bool TokenStore::ReloadIfRefreshedElsewhere() {
  const std::string previous_access = access_;
  if (Read() != SASL_OK) return false;
  if (access_ == previous_access || NeedsRefresh()) return false;
  log_->Write("TokenStore::Refresh: using token refreshed by another process");
  return true;
}

int TokenStore::Refresh() {
  if (refresh_attempts_ >= kMaxRefreshAttempts) {
    log_->Write("TokenStore::Refresh: exceeded maximum attempts");
    return SASL_BADPROT;
  }
  refresh_attempts_++;
  log_->Write("TokenStore::Refresh: attempt %d", refresh_attempts_);

  // Serialise refreshes across processes: many delivery processes notice an
  // expiring token at the same moment. Whoever gets the lock first refreshes;
  // the others pick up its result instead of requesting (and, with rotating
  // refresh tokens, overwriting) their own. Without the lock, carry on as
  // before rather than failing delivery.
  FileLock lock;
  if (enable_updates_ && lock.Acquire(log_, path_ + ".lock") &&
      ReloadIfRefreshedElsewhere()) {
    return SASL_OK;
  }

  const Config *config = Config::Get();
  const std::string grant_type = GrantType();
  const std::string client_id =
      override_client_id_.value_or(config->client_id());
  const std::string client_secret =
      override_client_secret_.value_or(config->client_secret());
  const std::string token_endpoint =
      override_token_endpoint_.value_or(config->token_endpoint());
  const std::string scope = override_scope_.value_or(config->scope());
  const std::string proxy = override_proxy_.value_or(config->proxy());
  const std::string ca_bundle_file =
      override_ca_bundle_file_.value_or(config->ca_bundle_file());
  const std::string ca_certs_dir =
      override_ca_certs_dir_.value_or(config->ca_certs_dir());

  if (grant_type == kGrantTypeClientCredentials && scope.empty()) {
    log_->Write("TokenStore::Refresh: grant_type %s requires a scope",
                grant_type.c_str());
    return SASL_FAIL;
  }

  std::string request = "grant_type=" + FormUrlEncode(grant_type) +
                        "&client_id=" + FormUrlEncode(client_id);
  // Public clients (e.g. Microsoft device flow) have no secret and must not
  // send one.
  if (!client_secret.empty())
    request += "&client_secret=" + FormUrlEncode(client_secret);
  if (grant_type == kGrantTypeRefreshToken)
    request += "&refresh_token=" + FormUrlEncode(refresh_);
  if (!scope.empty()) request += "&scope=" + FormUrlEncode(scope);

  std::string response;
  long response_code = 0;
  log_->Write("TokenStore::Refresh: token_endpoint: %s",
              token_endpoint.c_str());
  log_->Write(
      "TokenStore::Refresh: request: grant_type=%s, client_id=%s, "
      "client_secret=%s, refresh_token=%s, scope=%s",
      grant_type.c_str(), client_id.c_str(),
      RedactSecret(client_secret).c_str(),
      grant_type == kGrantTypeRefreshToken ? RedactSecret(refresh_).c_str()
                                           : "<not sent>",
      scope.empty() ? "<not sent>" : scope.c_str());

  std::string http_error;
  int err = HttpPost({.url = token_endpoint,
                      .data = request,
                      .proxy = proxy,
                      .ca_bundle_file = ca_bundle_file,
                      .ca_certs_dir = ca_certs_dir,
                      .response_code = &response_code,
                      .response = &response,
                      .error = &http_error});
  if (err != SASL_OK) {
    log_->Write("TokenStore::Refresh: http error: %s", http_error.c_str());
    return err;
  }

  if (response_code != 200) {
    // An error response carries the provider's reason and no tokens.
    log_->Write("TokenStore::Refresh: code=%ld, response=%s", response_code,
                response.c_str());
    LogTokenError(log_, response);
    log_->Write("TokenStore::Refresh: request failed");
    return SASL_BADPROT;
  }
  // A successful response carries the new access (and maybe refresh) token.
  log_->Write("TokenStore::Refresh: code=%ld, response=%s", response_code,
              RedactSecret(response).c_str());

  try {
    std::stringstream ss(response);
    Json::Value root;
    ss >> root;
    if (!root.isObject() || !root.isMember("access_token") ||
        !root.isMember("expires_in")) {
      log_->Write("TokenStore::Refresh: response doesn't contain access_token");
      return SASL_BADPROT;
    }
    const std::string access_token = root["access_token"].asString();
    if (access_token.empty()) {
      log_->Write("TokenStore::Refresh: empty access_token");
      return SASL_BADPROT;
    }
    const long long expiry_sec = stoll(root["expires_in"].asString());
    if (expiry_sec <= 0) {
      log_->Write("TokenStore::Refresh: invalid expiry");
      return SASL_BADPROT;
    }
    access_ = access_token;
    if (root.isMember("refresh_token")) {
      const std::string refresh_token = root["refresh_token"].asString();
      if (!refresh_token.empty() && refresh_token != refresh_) {
        log_->Write(
            "TokenStore::Refresh: response includes updated refresh token");
        refresh_ = refresh_token;
      }
    }
    expiry_ = time(nullptr) + static_cast<time_t>(expiry_sec);
  } catch (const std::exception &e) {
    log_->Write("TokenStore::Refresh: exception=%s", e.what());
    return SASL_FAIL;
  }

  return Write();
}

TokenStore::TokenStore(Log *log, const std::string &path, bool enable_updates)
    : log_(log), path_(path), enable_updates_(enable_updates) {}

int TokenStore::Read() {
  try {
    log_->Write("TokenStore::Read: file=%s", path_.c_str());

    std::ifstream file(path_);
    if (!file.good()) {
      log_->Write("TokenStore::Read: failed to open file %s: %s", path_.c_str(),
                  strerror(errno));
      return SASL_FAIL;
    }

    Json::Value root;
    file >> root;
    if (!root.isObject()) {
      log_->Write("TokenStore::Read: not a JSON object");
      return SASL_FAIL;
    }

    // Parse into locals first so that a bad file leaves the store unchanged.
    std::optional<std::string> client_id, client_secret, token_endpoint, proxy,
        ca_bundle_file, ca_certs_dir, grant_type, scope, user;
    ReadOverride(root, "client_id", &client_id);
    ReadOverride(root, "client_secret", &client_secret);
    ReadOverride(root, "token_endpoint", &token_endpoint);
    ReadOverride(root, "proxy", &proxy);
    ReadOverride(root, "ca_bundle_file", &ca_bundle_file);
    ReadOverride(root, "ca_certs_dir", &ca_certs_dir);
    ReadOverride(root, "grant_type", &grant_type);
    ReadOverride(root, "scope", &scope);
    ReadOverride(root, "user", &user);

    if (grant_type && !Config::IsValidGrantType(*grant_type)) {
      log_->Write("TokenStore::Read: invalid grant_type %s",
                  grant_type->c_str());
      return SASL_FAIL;
    }
    const std::string effective_grant_type =
        grant_type.value_or(Config::Get()->grant_type());

    std::optional<int> refresh_window;
    if (root.isMember("refresh_window")) {
      refresh_window = stoi(root["refresh_window"].asString());
      if (*refresh_window < 0) {
        log_->Write("TokenStore::Read: negative refresh_window");
        return SASL_FAIL;
      }
      if (*refresh_window == 0) {
        // Up to version 0.28, every token update wrote "refresh_window": "0"
        // into the file (unintentionally), which then silently overrode the
        // configured window. Treat 0 as "not set" so such files heal.
        refresh_window.reset();
      }
    }

    std::string refresh;
    if (root.isMember("refresh_token"))
      refresh = root["refresh_token"].asString();
    if (effective_grant_type == kGrantTypeRefreshToken && refresh.empty()) {
      log_->Write("TokenStore::Read: missing refresh_token");
      return SASL_FAIL;
    }

    std::string access;
    if (root.isMember("access_token")) access = root["access_token"].asString();
    time_t expiry = 0;
    // stoll, not stoi: Unix times from 2038-01-19 on do not fit in an int.
    if (root.isMember("expiry"))
      expiry = static_cast<time_t>(stoll(root["expiry"].asString()));

    override_client_id_ = client_id;
    override_client_secret_ = client_secret;
    override_token_endpoint_ = token_endpoint;
    override_proxy_ = proxy;
    override_ca_bundle_file_ = ca_bundle_file;
    override_ca_certs_dir_ = ca_certs_dir;
    override_grant_type_ = grant_type;
    override_scope_ = scope;
    override_refresh_window_ = refresh_window;
    refresh_ = refresh;
    access_ = access;
    expiry_ = expiry;
    user_ = user;

    log_->Write(
        "TokenStore::Read: grant_type=%s, refresh=%s, access=%s, user=%s",
        effective_grant_type.c_str(), RedactSecret(refresh_).c_str(),
        RedactSecret(access_).c_str(), user_.value_or("").c_str());
    return SASL_OK;

  } catch (const std::exception &e) {
    log_->Write("TokenStore::Read: exception=%s", e.what());
    return SASL_FAIL;
  }
}

int TokenStore::Write() {
  if (!enable_updates_) {
    log_->Write("TokenStore::Write: skipping write to %s", path_.c_str());
    return SASL_OK;
  }

  std::string contents;
  try {
    Json::Value root;
    if (!refresh_.empty()) root["refresh_token"] = refresh_;
    root["access_token"] = access_;
    root["expiry"] = std::to_string(expiry_);

    WriteOverride("user", user_, &root);

    WriteOverride("client_id", override_client_id_, &root);
    WriteOverride("client_secret", override_client_secret_, &root);
    WriteOverride("token_endpoint", override_token_endpoint_, &root);
    WriteOverride("proxy", override_proxy_, &root);
    WriteOverride("ca_bundle_file", override_ca_bundle_file_, &root);
    WriteOverride("ca_certs_dir", override_ca_certs_dir_, &root);
    WriteOverride("grant_type", override_grant_type_, &root);
    WriteOverride("scope", override_scope_, &root);

    if (override_refresh_window_) {
      root["refresh_window"] = std::to_string(*override_refresh_window_);
    }

    Json::StreamWriterBuilder builder;
    contents = Json::writeString(builder, root) + "\n";
  } catch (const std::exception &e) {
    log_->Write("TokenStore::Write: exception=%s", e.what());
    return SASL_FAIL;
  }

  return WriteFileAtomically(log_, path_, contents);
}

}  // namespace sasl_xoauth2
