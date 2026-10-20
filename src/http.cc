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

#include "http.h"

#include <curl/curl.h>
#include <sasl/sasl.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <string>

namespace sasl_xoauth2 {

namespace {

struct CURLDeleter final {
  void operator()(CURL *curl) const { curl_easy_cleanup(curl); }
};
using UniqueCURL = std::unique_ptr<CURL, CURLDeleter>;

constexpr char kUserAgent[] = "sasl xoauth2 token refresher";

// A token request runs inside the mail agent's delivery process, so it must
// never block indefinitely on an unresponsive endpoint or proxy.
constexpr long kConnectTimeoutSec = 10;
constexpr long kTotalTimeoutSec = 30;

// Token responses are a few KB at most; anything far larger is not one.
constexpr size_t kMaxResponseBytes = 256 * 1024;

class RequestContext {
 public:
  static size_t Read(char *data, size_t size, size_t items, void *context) {
    size *= items;

    auto *request = static_cast<RequestContext *>(context);
    size_t remaining = std::min(request->to_server_remaining_, size);
    memcpy(data, request->to_server_next_, remaining);
    request->to_server_next_ += remaining;
    request->to_server_remaining_ -= remaining;

    return remaining;
  }

  static size_t Write(char *data, size_t size, size_t items, void *context) {
    size *= items;

    auto *request = static_cast<RequestContext *>(context);
    if (request->from_server_.size() + size > kMaxResponseBytes) {
      request->response_too_large_ = true;
      return 0;  // Makes curl abort the transfer with CURLE_WRITE_ERROR.
    }
    request->from_server_.append(data, size);

    return size;
  }

  static int Seek(void *context, curl_off_t offset, int origin) {
    auto *request = static_cast<RequestContext *>(context);
    if (origin != SEEK_SET || offset != 0) return CURL_SEEKFUNC_FAIL;
    request->Rewind();
    return CURL_SEEKFUNC_OK;
  }

  RequestContext(const std::string &data) : to_server_(data) { Rewind(); }

  size_t to_server_size() const { return to_server_.size(); }

  std::string *mutable_from_server() { return &from_server_; }
  bool response_too_large() const { return response_too_large_; }

 private:
  void Rewind() {
    to_server_next_ = to_server_.c_str();
    to_server_remaining_ = to_server_.size();
  }

  std::string to_server_;
  const char *to_server_next_ = nullptr;
  size_t to_server_remaining_ = 0;

  std::string from_server_;
  bool response_too_large_ = false;
};

HttpIntercept s_intercept = {};

}  // namespace

std::string FormUrlEncode(const std::string &value) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(value.size() * 3);
  for (const unsigned char c : value) {
    // Explicit ranges rather than isalnum(), which depends on the locale.
    const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                            c == '_' || c == '~';
    if (unreserved) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0f]);
    }
  }
  return out;
}

void SetHttpInterceptForTesting(HttpIntercept intercept) {
  s_intercept = intercept;
}

int HttpPost(HttpPostOptions options) {
  if (s_intercept) return s_intercept(options);

  *options.response_code = 0;
  options.response->clear();

  // Declared before the handle, which refers to both until it is cleaned up.
  char transport_error[CURL_ERROR_SIZE] = {'\0'};
  RequestContext context(options.data);

  UniqueCURL curl(curl_easy_init());
  if (!curl) {
    *options.error = "Unable to create CURL handle.";
    return SASL_BADPROT;
  }

  // Behavior.
  curl_easy_setopt(curl.get(), CURLOPT_VERBOSE, false);
  curl_easy_setopt(curl.get(), CURLOPT_NOPROGRESS, true);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, true);

  // Errors.
  curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, transport_error);

  // Network.
  curl_easy_setopt(curl.get(), CURLOPT_URL, options.url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, kConnectTimeoutSec);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, kTotalTimeoutSec);

  // The request carries the client secret and refresh token: only ever send it
  // over HTTPS (this does not restrict the scheme used to reach a proxy).
#if LIBCURL_VERSION_NUM >= 0x075500  // 7.85.0
  curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "https");
#else
  curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
  curl_easy_setopt(curl.get(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

  // Certs.
  if (options.ca_certs_dir.empty()) {
    if (options.ca_bundle_file.empty()) {
      // Use default CA location.
    } else {
      curl_easy_setopt(curl.get(), CURLOPT_CAINFO, options.ca_bundle_file.c_str());
    }
  } else {
    curl_easy_setopt(curl.get(), CURLOPT_CAPATH, options.ca_certs_dir.c_str());
  }

  // HTTP. Token endpoints do not redirect; following a redirect could resend
  // the credentials (on 307/308) to wherever it points.
  curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, false);
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, kUserAgent);
  if (!options.proxy.empty())
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, options.proxy.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_POST, true);
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE,
                   static_cast<curl_off_t>(context.to_server_size()));

  // Callbacks.
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, &RequestContext::Write);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &context);
  curl_easy_setopt(curl.get(), CURLOPT_READFUNCTION, &RequestContext::Read);
  curl_easy_setopt(curl.get(), CURLOPT_READDATA, &context);
  curl_easy_setopt(curl.get(), CURLOPT_SEEKFUNCTION, &RequestContext::Seek);
  curl_easy_setopt(curl.get(), CURLOPT_SEEKDATA, &context);

  CURLcode err = curl_easy_perform(curl.get());

  if (context.response_too_large()) {
    *options.error =
        "Response exceeds " + std::to_string(kMaxResponseBytes) + " bytes.";
    return SASL_BADPROT;
  }

  if (err != CURLE_OK) {
    *options.error = transport_error;
    if (options.error->empty()) {
      *options.error = curl_easy_strerror(err);
      *options.error += " (no further error information)";
    }
    return SASL_BADPROT;
  }

  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, options.response_code);
  options.response->swap(*context.mutable_from_server());
  return SASL_OK;
}

}  // namespace sasl_xoauth2
