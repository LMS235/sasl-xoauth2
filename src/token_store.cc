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
#include <syslog.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <vector>

#include "client_assertion.h"
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
    // flock() works on read-only descriptors too, e.g. for a lock file that
    // another user created.
    if (fd_ < 0 && errno == EACCES)
      fd_ = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
  // Compare with the group the new file actually got (which, in a setgid
  // directory, is the directory's group rather than the writer's).
  struct stat created = {};
  const gid_t new_gid =
      (fstat(fd, &created) == 0) ? created.st_gid : static_cast<gid_t>(-1);
  if (have_existing && existing.st_gid != new_gid &&
      fchown(fd, static_cast<uid_t>(-1), existing.st_gid) != 0) {
    // The new file belongs to a different group, which must not inherit the
    // old group's access.
    log->Write("TokenStore::Write: unable to keep group of %s: %s",
               path.c_str(), strerror(errno));
    if (fchmod(fd, mode & ~S_IRWXG) != 0) {
      log->Write("TokenStore::Write: unable to set mode of %s: %s",
                 temp_path.c_str(), strerror(errno));
    }
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
           "an empty client_secret) or the client certificate";
  if (error == "unauthorized_client")
    return "the client is unknown in this tenant or may not use this grant "
           "type; check client_id, the tenant in token_endpoint, admin "
           "consent, and the app registration (e.g. 'Allow public client "
           "flows' for device flow)";
  if (error == "invalid_scope")
    return "the requested scope is not valid for this client; check scope";
  return nullptr;
}

// Errors that only go away when someone fixes the configuration or obtains new
// credentials; anything else (e.g. HTTP 429 or 5xx) may be transient.
bool IsPermanentTokenError(const std::string &error) {
  return error == "invalid_grant" || error == "invalid_client" ||
         error == "unauthorized_client" || error == "invalid_scope" ||
         error == "unsupported_grant_type" || error == "invalid_request";
}

struct TokenError {
  std::string error;
  std::string description;
};

TokenError ParseTokenError(const std::string &response) {
  TokenError result;
  try {
    std::stringstream ss(response);
    Json::Value root;
    ss >> root;
    if (root.isObject() && root.isMember("error")) {
      result.error = root["error"].asString();
      result.description = root.get("error_description", "").asString();
    }
  } catch (const std::exception &) {
    // Not JSON (e.g. an HTML error page from a proxy).
  }
  return result;
}

// Access tokens are refreshed long before they expire; if refreshing fails, a
// token with at least this much life left is still used.
constexpr time_t kMinRemainingLifetimeSec = 60;

// Upper bound for a token lifetime (expires_in) from the provider. Microsoft
// issues up to about 28 hours (continuous access evaluation).
constexpr long long kMaxTokenLifetimeSec = 7 * 24 * 3600;

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

int TokenStore::Fail(bool permanent, int err) {
  last_error_permanent_ = permanent;
  return err;
}

int TokenStore::GetAccessToken(std::string *token) {
  if (NeedsRefresh()) {
    log_->Write("TokenStore::GetAccessToken: token expired. refreshing.");
    int err = Refresh();
    if (err != SASL_OK) {
      // A refresh starts refresh_window seconds before the token expires. If
      // the provider is unreachable in that window, keep using the token
      // while it is still valid rather than deferring mail.
      const time_t remaining = expiry_ - time(nullptr);
      if (access_.empty() || remaining < kMinRemainingLifetimeSec) return err;
      log_->Write(
          "TokenStore::GetAccessToken: refresh failed, using the current "
          "token (valid for %lld more seconds)",
          static_cast<long long>(remaining));
    }
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
  last_error_permanent_ = false;
  if (refresh_attempts_ >= kMaxRefreshAttempts) {
    log_->Error("token request for %s: exceeded maximum attempts",
                path_.c_str());
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

  int err = RequestToken();
  if (err != SASL_OK) return err;

  if (Write() != SASL_OK) {
    // The new token works; only storing it failed (e.g. a read-only file
    // system, a full disk, or wrong ownership of the token directory). Use it
    // anyway, but report the problem regardless of the log settings: until it
    // is fixed, every connection requests a new token.
    syslog(LOG_ERR,
           "[sasl-xoauth2] unable to update token file %s; using the new token "
           "without storing it. Check that the mail system can write to the "
           "token directory.",
           EscapeForLog(path_).c_str());
    log_->Write("TokenStore::Refresh: unable to store the new token");
  }
  return SASL_OK;
}

int TokenStore::RequestToken() {
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
  const std::string certificate_file =
      override_client_certificate_file_.value_or(
          config->client_certificate_file());
  std::string private_key_file = override_client_private_key_file_.value_or(
      config->client_private_key_file());
  if (private_key_file.empty()) private_key_file = certificate_file;
  const bool use_certificate = !certificate_file.empty();

  const std::string endpoint_for_log = EscapeForLog(token_endpoint);
  const std::string path_for_log = EscapeForLog(path_);

  if (grant_type == kGrantTypeClientCredentials && scope.empty()) {
    log_->Error("token request for %s: grant_type %s requires a scope",
                path_for_log.c_str(), grant_type.c_str());
    return Fail(/*permanent=*/true, SASL_FAIL);
  }
  if (grant_type == kGrantTypeClientCredentials && !use_certificate &&
      client_secret.empty()) {
    log_->Error(
        "token request for %s: grant_type %s requires a client certificate "
        "or a client_secret",
        path_for_log.c_str(), grant_type.c_str());
    return Fail(/*permanent=*/true, SASL_FAIL);
  }

  // A token file that sends requests elsewhere (another endpoint, proxy or CA)
  // must bring its own client secret: the configured one is only sent where
  // the configuration says. (A client assertion names its endpoint as
  // audience, so it is useless anywhere else and needs no such check.)
  const auto differs = [](const std::optional<std::string> &override_value,
                          const std::string &config_value) {
    return override_value && *override_value != config_value;
  };
  const bool connection_overridden =
      differs(override_token_endpoint_, config->token_endpoint()) ||
      differs(override_proxy_, config->proxy()) ||
      differs(override_ca_bundle_file_, config->ca_bundle_file()) ||
      differs(override_ca_certs_dir_, config->ca_certs_dir());
  if (!use_certificate && connection_overridden && !override_client_secret_ &&
      !config->client_secret().empty()) {
    log_->Error(
        "token request for %s: the token file overrides token_endpoint, "
        "proxy or CA settings but not client_secret; refusing to send the "
        "configured client_secret there (set client_secret in the token "
        "file)",
        path_for_log.c_str());
    return Fail(/*permanent=*/true, SASL_FAIL);
  }

  std::string request = "grant_type=" + FormUrlEncode(grant_type) +
                        "&client_id=" + FormUrlEncode(client_id);
  std::string credential_for_log;
  if (use_certificate) {
    std::string assertion, assertion_error;
    if (!CreateClientAssertion(certificate_file, private_key_file, client_id,
                               token_endpoint, time(nullptr), &assertion,
                               &assertion_error)) {
      log_->Error("token request for %s: client certificate: %s",
                  path_for_log.c_str(), EscapeForLog(assertion_error).c_str());
      return Fail(/*permanent=*/true, SASL_FAIL);
    }
    request += "&client_assertion_type=" + FormUrlEncode(kClientAssertionType) +
               "&client_assertion=" + FormUrlEncode(assertion);
    credential_for_log =
        "client_assertion=<certificate " + EscapeForLog(certificate_file) + ">";
  } else {
    // Public clients (e.g. Microsoft device flow) have no secret and must not
    // send one.
    if (!client_secret.empty())
      request += "&client_secret=" + FormUrlEncode(client_secret);
    credential_for_log = "client_secret=" + RedactSecret(client_secret);
  }
  if (grant_type == kGrantTypeRefreshToken)
    request += "&refresh_token=" + FormUrlEncode(refresh_);
  // The scope is needed (only) to request app-only tokens. Refresh token
  // requests leave it out and get the scopes originally granted; this also
  // ignores the "scope" field older tools copied into Gmail token files.
  const bool send_scope = (grant_type == kGrantTypeClientCredentials);
  if (send_scope) request += "&scope=" + FormUrlEncode(scope);

  std::string response;
  long response_code = 0;
  log_->Write("TokenStore::Refresh: token_endpoint: %s",
              endpoint_for_log.c_str());
  log_->Write(
      "TokenStore::Refresh: request: grant_type=%s, client_id=%s, %s, "
      "refresh_token=%s, scope=%s",
      grant_type.c_str(), EscapeForLog(client_id).c_str(),
      credential_for_log.c_str(),
      grant_type == kGrantTypeRefreshToken ? RedactSecret(refresh_).c_str()
                                           : "<not sent>",
      send_scope ? EscapeForLog(scope).c_str() : "<not sent>");

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
    log_->Error("token request for %s to %s failed: %s", path_for_log.c_str(),
                endpoint_for_log.c_str(), EscapeForLog(http_error).c_str());
    return Fail(/*permanent=*/false, err);
  }

  if (response_code != 200) {
    // An error response carries the provider's reason and no tokens.
    log_->Write("TokenStore::Refresh: code=%ld, response=%s", response_code,
                EscapeForLog(response).c_str());
    const TokenError token_error = ParseTokenError(response);
    const char *hint = HintForTokenError(token_error.error);
    log_->Error("token request for %s to %s failed: HTTP %ld %s%s%s%s%s",
                path_for_log.c_str(), endpoint_for_log.c_str(), response_code,
                token_error.error.empty()
                    ? "(no error details)"
                    : EscapeForLog(token_error.error, 64).c_str(),
                token_error.description.empty() ? "" : ": ",
                EscapeForLog(token_error.description, 512).c_str(),
                hint ? "; hint: " : "", hint ? hint : "");
    return Fail(IsPermanentTokenError(token_error.error), SASL_BADPROT);
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
      log_->Error(
          "token request for %s: response lacks access_token or "
          "expires_in",
          path_for_log.c_str());
      return Fail(/*permanent=*/false, SASL_BADPROT);
    }
    const std::string access_token = root["access_token"].asString();
    long long expiry_sec = 0;
    const Json::Value &expires_in = root["expires_in"];
    const bool expiry_ok =
        expires_in.isIntegral()
            ? (expiry_sec = expires_in.asLargestInt(), true)
            : (expires_in.isString() &&
               ParseInteger(expires_in.asString(), &expiry_sec));
    if (access_token.empty() || !expiry_ok || expiry_sec <= 0) {
      log_->Error("token request for %s: invalid access_token or expires_in",
                  path_for_log.c_str());
      return Fail(/*permanent=*/false, SASL_BADPROT);
    }
    if (expiry_sec > kMaxTokenLifetimeSec) {
      log_->Write("TokenStore::Refresh: limiting token lifetime of %lld s",
                  expiry_sec);
      expiry_sec = kMaxTokenLifetimeSec;
    }
    if (expiry_sec <= RefreshWindow()) {
      log_->Write(
          "TokenStore::Refresh: token lifetime (%lld s) is not longer than "
          "refresh_window (%d s); every connection will request a new token",
          expiry_sec, RefreshWindow());
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
    log_->Error("token request for %s: unreadable response: %s",
                path_for_log.c_str(), EscapeForLog(e.what()).c_str());
    return Fail(/*permanent=*/false, SASL_FAIL);
  }

  return SASL_OK;
}

TokenStore::TokenStore(Log *log, const std::string &path, bool enable_updates)
    : log_(log), path_(path), enable_updates_(enable_updates) {}

int TokenStore::Read() {
  try {
    log_->Write("TokenStore::Read: file=%s", path_.c_str());

    std::ifstream file(path_);
    if (!file.good()) {
      log_->Error("unable to read token file %s: %s",
                  EscapeForLog(path_).c_str(), strerror(errno));
      return Fail(/*permanent=*/true, SASL_FAIL);
    }

    Json::Value root;
    file >> root;
    if (!root.isObject()) {
      log_->Error("token file %s: not a JSON object",
                  EscapeForLog(path_).c_str());
      return Fail(/*permanent=*/true, SASL_FAIL);
    }

    // Parse into locals first so that a bad file leaves the store unchanged.
    std::optional<std::string> client_id, client_secret, token_endpoint, proxy,
        ca_bundle_file, ca_certs_dir, grant_type, scope, user,
        client_certificate_file, client_private_key_file;
    ReadOverride(root, "client_id", &client_id);
    ReadOverride(root, "client_secret", &client_secret);
    ReadOverride(root, "token_endpoint", &token_endpoint);
    ReadOverride(root, "proxy", &proxy);
    ReadOverride(root, "ca_bundle_file", &ca_bundle_file);
    ReadOverride(root, "ca_certs_dir", &ca_certs_dir);
    ReadOverride(root, "grant_type", &grant_type);
    ReadOverride(root, "scope", &scope);
    ReadOverride(root, "user", &user);
    ReadOverride(root, "client_certificate_file", &client_certificate_file);
    ReadOverride(root, "client_private_key_file", &client_private_key_file);

    if (grant_type && !Config::IsValidGrantType(*grant_type)) {
      log_->Error("token file %s: invalid grant_type %s",
                  EscapeForLog(path_).c_str(),
                  EscapeForLog(*grant_type, 64).c_str());
      return Fail(/*permanent=*/true, SASL_FAIL);
    }
    const std::string effective_grant_type =
        grant_type.value_or(Config::Get()->grant_type());

    std::optional<int> refresh_window;
    if (root.isMember("refresh_window")) {
      long long value = 0;
      if (!ParseInteger(root["refresh_window"].asString(), &value) ||
          value < 0 || value > kMaxRefreshWindow) {
        log_->Error("token file %s: refresh_window must be 0-%d seconds",
                    EscapeForLog(path_).c_str(), kMaxRefreshWindow);
        return Fail(/*permanent=*/true, SASL_FAIL);
      }
      refresh_window = static_cast<int>(value);
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
      log_->Error("token file %s: missing refresh_token",
                  EscapeForLog(path_).c_str());
      return Fail(/*permanent=*/true, SASL_FAIL);
    }

    std::string access;
    if (root.isMember("access_token")) access = root["access_token"].asString();
    time_t expiry = 0;
    // stoll, not stoi: Unix times from 2038-01-19 on do not fit in an int.
    if (root.isMember("expiry")) {
      long long value = 0;
      if (ParseInteger(root["expiry"].asString(), &value)) {
        expiry = static_cast<time_t>(value);
      } else {
        // Not fatal: the token is merely treated as expired and refreshed.
        log_->Write("TokenStore::Read: ignoring invalid expiry");
      }
    }

    override_client_id_ = client_id;
    override_client_secret_ = client_secret;
    override_token_endpoint_ = token_endpoint;
    override_proxy_ = proxy;
    override_ca_bundle_file_ = ca_bundle_file;
    override_ca_certs_dir_ = ca_certs_dir;
    override_grant_type_ = grant_type;
    override_scope_ = scope;
    override_client_certificate_file_ = client_certificate_file;
    override_client_private_key_file_ = client_private_key_file;
    override_refresh_window_ = refresh_window;
    refresh_ = refresh;
    access_ = access;
    expiry_ = expiry;
    user_ = user;

    log_->Write(
        "TokenStore::Read: grant_type=%s, refresh=%s, access=%s, user=%s",
        effective_grant_type.c_str(), RedactSecret(refresh_).c_str(),
        RedactSecret(access_).c_str(),
        EscapeForLog(user_.value_or("")).c_str());
    return SASL_OK;

  } catch (const std::exception &e) {
    log_->Error("unable to read token file %s: %s", EscapeForLog(path_).c_str(),
                EscapeForLog(e.what()).c_str());
    last_error_permanent_ = true;
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
    WriteOverride("client_certificate_file", override_client_certificate_file_,
                  &root);
    WriteOverride("client_private_key_file", override_client_private_key_file_,
                  &root);

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
