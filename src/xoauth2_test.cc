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

#include <assert.h>
#include <json/json.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "config.h"
#include "http.h"
#include "log.h"
#include "module.h"
#include "token_store.h"

const std::string kUserName = "abc@def.com";

constexpr char kTempFileTemplate[] = "/tmp/sasl_xoauth2_test_token.XXXXXX";
constexpr char kTokenTemplate[] =
    R"({"access_token": "%s", "refresh_token": "%s", "expiry": "%s"})";
constexpr char kTokenTemplateWithUser[] =
    R"({"access_token": "%s", "refresh_token": "%s", "expiry": "%s",
        "user": "%s"})";
constexpr char kTokenTemplateWithOverrides[] =
    R"({"access_token": "%s", "refresh_token": "%s", "expiry": "%s",
        "token_endpoint": "%s", "client_secret": "%s"})";

constexpr char kServerPermanentError[] =
    R"({"status":"500","schemes":"Bearer","scope":"https://mail.google.com/"})";
constexpr char kServerTokenExpired[] =
    R"({"status":"401","schemes":"Bearer","scope":"https://mail.google.com/"})";

std::string s_password;
std::vector<std::string> s_cleanup_files;

FILE *OpenTempTokenFile() {
  char temp_template[sizeof(kTempFileTemplate)];
  strcpy(temp_template, kTempFileTemplate);
  int fd = mkstemp(temp_template);
  s_password = temp_template;
  s_cleanup_files.push_back(s_password);
  return fdopen(fd, "w");
}

void SetPasswordToValidToken() {
  FILE *f = OpenTempTokenFile();
  std::string expiry_str = std::to_string(time(nullptr) + 3600);
  fprintf(f, kTokenTemplate, "access", "refresh", expiry_str.c_str());
  fclose(f);
}

void SetPasswordToValidTokenAfter2038() {
  FILE *f = OpenTempTokenFile();
  // 2100-01-01T00:00:00Z: past the 32-bit time_t limit (2038-01-19).
  fprintf(f, kTokenTemplate, "access", "refresh", "4102444800");
  fclose(f);
}

void SetPasswordToValidTokenWithUserOverride(const std::string &user) {
  FILE *f = OpenTempTokenFile();
  std::string expiry_str = std::to_string(time(nullptr) + 3600);
  fprintf(f, kTokenTemplateWithUser, "access", "refresh", expiry_str.c_str(),
          user.c_str());
  fclose(f);
}

void SetPasswordToExpiredTokenWithOtherOverrides(
    const std::string &token_endpoint, const std::string &client_secret) {
  FILE *f = OpenTempTokenFile();
  std::string expiry_str = "0";
  fprintf(f, kTokenTemplateWithOverrides, "access", "refresh",
          expiry_str.c_str(), token_endpoint.c_str(), client_secret.c_str());
  fclose(f);
}

void SetPasswordToInvalidToken() {
  FILE *f = OpenTempTokenFile();
  std::string expiry_str = std::to_string(0);
  fprintf(f, "invalid");
  fclose(f);
}

void SetPasswordToExpiredToken() {
  FILE *f = OpenTempTokenFile();
  std::string expiry_str = "0";
  fprintf(f, kTokenTemplate, "access", "refresh", expiry_str.c_str());
  fclose(f);
}

void SetPasswordToInvalidPath() { s_password = "/tmp/this/path/is/not/valid"; }

void Cleanup() {
  for (const auto &file : s_cleanup_files) {
    unlink(file.c_str());
    unlink((file + ".lock").c_str());
  }
}

// Writes |contents| to a new temporary token file, which becomes s_password.
void SetPasswordToTokenFile(const std::string &contents) {
  FILE *f = OpenTempTokenFile();
  fputs(contents.c_str(), f);
  fclose(f);
}

std::string ExpiryIn(int seconds) {
  return std::to_string(time(nullptr) + seconds);
}

// A token file with access token "access" and refresh token "r" expiring
// |seconds| from now, plus |extra| members (each followed by a comma).
std::string TokenFileExpiringIn(int seconds, const std::string &extra = "") {
  return R"({"access_token": "access", "refresh_token": "r", )" + extra +
         R"("expiry": ")" + ExpiryIn(seconds) + R"("})";
}

std::string ReadFile(const std::string &path) {
  std::ifstream f(path);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

Json::Value ReadJsonFile(const std::string &path) {
  std::ifstream f(path);
  Json::Value root;
  f >> root;
  return root;
}

// Answers token requests with a fresh access token, recording each request.
struct FakeTokenEndpoint {
  int calls = 0;
  std::string last_request;
  std::string response =
      R"({"access_token": "refreshed_access", "expires_in": 3600})";
  long response_code = 200;

  void Install() {
    sasl_xoauth2::SetHttpInterceptForTesting(
        [this](sasl_xoauth2::HttpPostOptions options) {
          calls++;
          last_request = options.data;
          *options.response = response;
          *options.response_code = response_code;
          return SASL_OK;
        });
  }
};

int DefaultHttpIntercept(sasl_xoauth2::HttpPostOptions options) {
  fprintf(stderr, "TEST: default http intercept for url=%s\n",
          options.url.c_str());
  return SASL_FAIL;
}

#define TEST_ABORT(x)                                                     \
  do {                                                                    \
    bool __result = (x);                                                  \
    if (!__result) {                                                      \
      fprintf(stderr, "TEST ASSERTION FAILED at %s:%d: %s -- ABORTING\n", \
              __FILE__, __LINE__, #x);                                    \
      Cleanup();                                                          \
      exit(1);                                                            \
    }                                                                     \
  } while (0)

#define TEST_ASSERT(x)                                                  \
  do {                                                                  \
    bool __result = (x);                                                \
    if (!__result) {                                                    \
      fprintf(stderr, "TEST ASSERTION FAILED at %s:%d: %s\n", __FILE__, \
              __LINE__, #x);                                            \
      return false;                                                     \
    }                                                                   \
  } while (0)

#define TEST_ASSERT_OK(x)                                                 \
  do {                                                                    \
    int __result = (x);                                                   \
    if (__result != SASL_OK) {                                            \
      fprintf(stderr, "TEST ASSERTION FAILED at %s:%d: %s returned %d\n", \
              __FILE__, __LINE__, #x, __result);                          \
      return false;                                                       \
    }                                                                     \
  } while (0)

void FakeFree(void *ptr) { free(ptr); }

void *FakeMalloc(size_t size) { return malloc(size); }

int FakeGetAuthName(void *, int id, const char **result, unsigned int *len) {
  assert(id == SASL_CB_AUTHNAME);
  *result = kUserName.c_str();
  *len = kUserName.size();
  return 0;
}

int FakeGetPassword(sasl_conn_t *, void *, int id, sasl_secret_t **pass) {
  assert(id == SASL_CB_PASS);
  auto *p = static_cast<sasl_secret_t *>(
      malloc(sizeof(sasl_secret_t) + s_password.size() + 1));
  p->len = s_password.size();
  strcpy(reinterpret_cast<char *>(p->data), s_password.c_str());
  *pass = p;
  return SASL_OK;
}

int FakeGetCallbackAll(sasl_conn_t *, unsigned long id, sasl_callback_ft *ft,
                       void **context) {
  if (id == SASL_CB_AUTHNAME)
    *ft = reinterpret_cast<sasl_callback_ft>(&FakeGetAuthName);
  else if (id == SASL_CB_PASS)
    *ft = reinterpret_cast<sasl_callback_ft>(&FakeGetPassword);
  else
    return SASL_FAIL;
  return SASL_OK;
}

int FakeGetCallbackNone(sasl_conn_t *, unsigned long, sasl_callback_ft *,
                        void **) {
  return SASL_FAIL;
}

int FakeCanonUser(sasl_conn_t *, const char *, unsigned int, unsigned int,
                  sasl_out_params_t *) {
  return SASL_OK;
}

class PlugCleanup {
 public:
  PlugCleanup(sasl_utils_t *utils, sasl_client_plug_t plug, void *context)
      : utils_(utils), plug_(plug), context_(context) {}

  ~PlugCleanup() { plug_.mech_dispose(context_, utils_); }

 private:
  sasl_utils_t *utils_;
  sasl_client_plug_t plug_;
  void *context_;
};

void PrintTestName(const char *name) {
  fprintf(stderr, "\n");
  fprintf(stderr, "TEST: %s\n", name);
  fprintf(stderr, "%s\n", std::string(strlen(name) + 6, '=').c_str());
}

bool TestWithPrompts(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackNone;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  auto *prompt_need =
      static_cast<sasl_interact_t *>(malloc(sizeof(sasl_interact_t) * 3));
  memset(prompt_need, 0, sizeof(sasl_interact_t) * 3);

  sasl_interact_t *cred_auth_name = prompt_need + 0;
  cred_auth_name->id = SASL_CB_AUTHNAME;
  cred_auth_name->result = kUserName.data();
  cred_auth_name->len = kUserName.size();

  sasl_interact_t *cred_pass = prompt_need + 1;
  cred_pass->id = SASL_CB_PASS;
  cred_pass->result = s_password.data();
  cred_pass->len = s_password.size();

  sasl_interact_t *end = prompt_need + 2;
  end->id = SASL_CB_LIST_END;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, &prompt_need,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithoutPrompts(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackNone;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  auto *prompt_need =
      static_cast<sasl_interact_t *>(malloc(sizeof(sasl_interact_t) * 1));
  memset(prompt_need, 0, sizeof(sasl_interact_t) * 1);

  sasl_interact_t *end = prompt_need + 0;
  end->id = SASL_CB_LIST_END;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  int err = plug.mech_step(context, &params, nullptr, 0, &prompt_need,
                           &to_server, &to_server_len, &out_params);
  TEST_ASSERT(err == SASL_INTERACT);
  TEST_ASSERT(to_server_len == 0);

  sasl_interact_t *p = prompt_need;
  while (p && p->id != SASL_CB_LIST_END) {
    fprintf(stderr, "p: id=%lu, challenge=%s\n", p->id, p->challenge);
    if (p->id == SASL_CB_AUTHNAME) {
      p->result = kUserName.c_str();
      p->len = kUserName.size();
    } else if (p->id == SASL_CB_PASS) {
      p->result = s_password.c_str();
      p->len = s_password.size();
    } else {
      fprintf(stderr, "unexpected id=%lu\n", p->id);
      TEST_ASSERT(false);
    }
    p++;
  }

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, &prompt_need,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithCallbacks(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithExpiryAfter2038(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidTokenAfter2038();
  bool intercept_called = false;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&intercept_called](sasl_xoauth2::HttpPostOptions options) {
        intercept_called = true;
        return SASL_FAIL;
      });

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  // The token is valid until 2100, so it is sent as-is with no refresh.
  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  TEST_ASSERT(strstr(to_server, "Bearer access") != nullptr);
  TEST_ASSERT(!intercept_called);

  return true;
}

bool TestWithCallbacksAndUserOverride(sasl_client_plug_t plug) {
  const std::string kUserNameOverride = "override@foo.com";

  PrintTestName(__func__);
  SetPasswordToValidTokenWithUserOverride(kUserNameOverride);
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) == nullptr);
  TEST_ASSERT(strstr(to_server, kUserNameOverride.c_str()) != nullptr);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithCallbacksAndOtherOverrides(sasl_client_plug_t plug) {
  const std::string kTokenEndpointOverride = "http://foo.com";
  const std::string kClientSecretOverride = "";

  PrintTestName(__func__);
  SetPasswordToExpiredTokenWithOtherOverrides(kTokenEndpointOverride,
                                              kClientSecretOverride);
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  std::string intercept_token_endpoint, intercept_req_data;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&intercept_token_endpoint,
       &intercept_req_data](sasl_xoauth2::HttpPostOptions options) {
        *options.response =
            R"({"access_token": "refreshed_access", "expires_in": 3600})";
        *options.response_code = 200;
        intercept_token_endpoint = options.url;
        intercept_req_data = options.data;
        return SASL_OK;
      });

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, "refreshed_access") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  fprintf(stderr, "intercept_token_endpoint=[%s], intercept_req_data=[%s]\n",
          intercept_token_endpoint.c_str(), intercept_req_data.c_str());
  TEST_ASSERT(intercept_token_endpoint == kTokenEndpointOverride);
  // The empty override wins over the config's secret, and an empty secret is
  // not sent at all (public clients must not send one).
  TEST_ASSERT(intercept_req_data.find("client_secret") == std::string::npos);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithPermanentError(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  int err = plug.mech_step(context, &params, kServerPermanentError,
                           sizeof(kServerPermanentError), nullptr, &to_server,
                           &to_server_len, &out_params);
  fprintf(stderr, "err=%d\n", err);
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(err != SASL_OK);
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestWithTokenExpiredError(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToValidToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);

  bool intercept_called = false;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&intercept_called](sasl_xoauth2::HttpPostOptions options) {
        *options.response = R"({"access_token": "access", "expires_in": 3600})";
        *options.response_code = 200;
        intercept_called = true;
        return SASL_OK;
      });

  int err = plug.mech_step(context, &params, kServerTokenExpired,
                           sizeof(kServerTokenExpired), nullptr, &to_server,
                           &to_server_len, &out_params);
  fprintf(stderr, "err=%d\n", err);
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(err == SASL_TRYAGAIN);
  TEST_ASSERT(to_server_len == 0);
  TEST_ASSERT(intercept_called);

  return true;
}

bool TestPreemptiveTokenRefresh(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  bool intercept_called = false;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&intercept_called](sasl_xoauth2::HttpPostOptions options) {
        *options.response =
            R"({"access_token": "refreshed_access", "expires_in": 3600})";
        *options.response_code = 200;
        intercept_called = true;
        return SASL_OK;
      });

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  fprintf(stderr, "to_server=[%s], len=%d\n", to_server, to_server_len);
  TEST_ASSERT(strstr(to_server, "Bearer") != nullptr);
  TEST_ASSERT(strstr(to_server, "refreshed_access") != nullptr);
  TEST_ASSERT(strstr(to_server, kUserName.c_str()) != nullptr);
  TEST_ASSERT(intercept_called);

  TEST_ASSERT_OK(plug.mech_step(context, &params, "", 0, nullptr, &to_server,
                                &to_server_len, &out_params));
  TEST_ASSERT(to_server_len == 0);

  return true;
}

bool TestFailedPreemptiveTokenRefresh(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  bool intercept_called = false;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&intercept_called](sasl_xoauth2::HttpPostOptions options) {
        *options.response = "";
        *options.response_code = 400;
        intercept_called = true;
        return SASL_OK;
      });

  int err = plug.mech_step(context, &params, nullptr, 0, nullptr, &to_server,
                           &to_server_len, &out_params);
  fprintf(stderr, "err=%d\n", err);
  TEST_ASSERT(err != SASL_OK);
  TEST_ASSERT(to_server_len == 0);
  TEST_ASSERT(intercept_called);

  return true;
}

bool TestEscapeForLog() {
  PrintTestName(__func__);
  TEST_ASSERT(sasl_xoauth2::EscapeForLog("user@example.com") ==
              "user@example.com");
  TEST_ASSERT(sasl_xoauth2::EscapeForLog("a\nb\1c\\") == "a\\x0ab\\x01c\\x5c");
  return true;
}

bool TestRedactSecret() {
  PrintTestName(__func__);
  TEST_ASSERT(sasl_xoauth2::RedactSecret("") == "<empty>");
  const std::string redacted = sasl_xoauth2::RedactSecret("ya29.secret");
  TEST_ASSERT(redacted == "<redacted, 11 bytes>");
  TEST_ASSERT(redacted.find("secret") == std::string::npos);
  return true;
}

bool TestFormUrlEncode() {
  PrintTestName(__func__);
  TEST_ASSERT(sasl_xoauth2::FormUrlEncode("") == "");
  TEST_ASSERT(sasl_xoauth2::FormUrlEncode("AZaz09-._~") == "AZaz09-._~");
  TEST_ASSERT(sasl_xoauth2::FormUrlEncode("a+b&c=d/e f") ==
              "a%2Bb%26c%3Dd%2Fe%20f");
  TEST_ASSERT(sasl_xoauth2::FormUrlEncode("\xff\x01") == "%FF%01");
  return true;
}

// The configured refresh_window (default 300s) applies: a token with 120s
// left is refreshed before use.
bool TestRefreshWindowFromConfig() {
  PrintTestName(__func__);
  SetPasswordToTokenFile(TokenFileExpiringIn(120));
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT_OK(store->GetAccessToken(&token));
  TEST_ASSERT(endpoint.calls == 1);
  TEST_ASSERT(token == "refreshed_access");
  // Nothing (in particular no refresh_window) is added to the token file.
  TEST_ASSERT(!ReadJsonFile(s_password).isMember("refresh_window"));
  return true;
}

// Older versions wrote "refresh_window": "0" into every token file; that must
// not override the configured window, and is dropped on the next write.
bool TestLegacyZeroRefreshWindowIgnored() {
  PrintTestName(__func__);
  SetPasswordToTokenFile(TokenFileExpiringIn(120, R"("refresh_window": "0",)"));
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT_OK(store->GetAccessToken(&token));
  TEST_ASSERT(endpoint.calls == 1);
  TEST_ASSERT(!ReadJsonFile(s_password).isMember("refresh_window"));
  return true;
}

bool TestRefreshWindowOverrideInTokenFile() {
  PrintTestName(__func__);
  SetPasswordToTokenFile(
      TokenFileExpiringIn(120, R"("refresh_window": "30",)"));
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT_OK(store->GetAccessToken(&token));
  TEST_ASSERT(endpoint.calls == 0);
  TEST_ASSERT(token == "access");
  return true;
}

bool CheckModeKeptAcrossRefresh(mode_t initial_mode, mode_t expected_mode) {
  SetPasswordToExpiredToken();
  TEST_ASSERT(chmod(s_password.c_str(), initial_mode) == 0);
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  const mode_t old_umask = umask(022);
  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  const int err = store->Refresh();
  umask(old_umask);
  TEST_ASSERT_OK(err);

  struct stat st = {};
  TEST_ASSERT(stat(s_password.c_str(), &st) == 0);
  fprintf(stderr, "mode: initial=%o, after refresh=%o\n", initial_mode,
          st.st_mode & 07777);
  TEST_ASSERT((st.st_mode & 07777) == expected_mode);
  TEST_ASSERT(ReadJsonFile(s_password)["access_token"].asString() ==
              "refreshed_access");
  return true;
}

// The token file holds secrets: an update must not widen its permissions.
bool TestTokenFilePermissionsKept() {
  PrintTestName(__func__);
  TEST_ASSERT(CheckModeKeptAcrossRefresh(0600, 0600));
  TEST_ASSERT(CheckModeKeptAcrossRefresh(0640, 0640));
  // World access is never carried over.
  TEST_ASSERT(CheckModeKeptAcrossRefresh(0644, 0640));
  return true;
}

bool TestRequestIsFormEncoded() {
  PrintTestName(__func__);
  SetPasswordToTokenFile(R"({"access_token": "a", "expiry": "0",
                             "refresh_token": "0.AX+y/z=",
                             "client_secret": "s~e+c&r=e/t",
                             "scope": "offline_access https://outlook.office.com/SMTP.Send"})");
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  TEST_ASSERT_OK(store->Refresh());
  fprintf(stderr, "request=[%s]\n", endpoint.last_request.c_str());
  // The scope is only sent for client credentials; refresh token requests
  // get the originally granted scopes (older tools put Google's "scope" into
  // token files).
  TEST_ASSERT(endpoint.last_request ==
              "grant_type=refresh_token&client_id=dummy%20client%20id"
              "&client_secret=s~e%2Bc%26r%3De%2Ft"
              "&refresh_token=0.AX%2By%2Fz%3D");
  return true;
}

bool TestRotatedRefreshTokenStored() {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  FakeTokenEndpoint endpoint;
  endpoint.response = R"({"access_token": "new_access", "expires_in": 3599,
                          "refresh_token": "new_refresh"})";
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT_OK(store->GetAccessToken(&token));
  const Json::Value root = ReadJsonFile(s_password);
  TEST_ASSERT(root["refresh_token"].asString() == "new_refresh");
  TEST_ASSERT(root["access_token"].asString() == "new_access");
  const long long expiry = std::stoll(root["expiry"].asString());
  TEST_ASSERT(expiry > time(nullptr) + 3500);
  return true;
}

// Microsoft's app-only flow: no refresh token, a .default scope, and the
// mailbox given as user.
bool TestClientCredentialsGrant(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToTokenFile(R"({"grant_type": "client_credentials",
                             "scope": "https://outlook.office365.com/.default",
                             "client_secret": "secret",
                             "user": "mailbox@contoso.com"})");
  FakeTokenEndpoint endpoint;
  endpoint.response =
      R"({"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599,
          "access_token": "app_only_access"})";
  endpoint.Install();

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT_OK(plug.mech_step(context, &params, nullptr, 0, nullptr,
                                &to_server, &to_server_len, &out_params));
  const std::string response(to_server, to_server_len);
  TEST_ASSERT(response ==
              "user=mailbox@contoso.com\1auth=Bearer app_only_access\1\1");

  fprintf(stderr, "request=[%s]\n", endpoint.last_request.c_str());
  TEST_ASSERT(endpoint.calls == 1);
  TEST_ASSERT(endpoint.last_request ==
              "grant_type=client_credentials&client_id=dummy%20client%20id"
              "&client_secret=secret"
              "&scope=https%3A%2F%2Foutlook.office365.com%2F.default");

  const Json::Value root = ReadJsonFile(s_password);
  TEST_ASSERT(!root.isMember("refresh_token"));
  TEST_ASSERT(root["grant_type"].asString() == "client_credentials");
  TEST_ASSERT(root["access_token"].asString() == "app_only_access");
  return true;
}

bool TestClientCredentialsWithoutScopeFails() {
  PrintTestName(__func__);
  SetPasswordToTokenFile(R"({"grant_type": "client_credentials"})");
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT(store->GetAccessToken(&token) != SASL_OK);
  TEST_ASSERT(endpoint.calls == 0);
  return true;
}

bool TestInvalidTokenFilesRejected() {
  PrintTestName(__func__);
  auto log = sasl_xoauth2::Log::Create();

  SetPasswordToTokenFile(R"({"grant_type": "password", "refresh_token": "r"})");
  TEST_ASSERT(!sasl_xoauth2::TokenStore::Create(log.get(), s_password));

  // A refresh_token grant needs a refresh token.
  SetPasswordToTokenFile(R"({"access_token": "a"})");
  TEST_ASSERT(!sasl_xoauth2::TokenStore::Create(log.get(), s_password));

  SetPasswordToTokenFile(R"(["not", "an", "object"])");
  TEST_ASSERT(!sasl_xoauth2::TokenStore::Create(log.get(), s_password));

  SetPasswordToTokenFile(R"({"refresh_token": "r", "refresh_window": "-1"})");
  TEST_ASSERT(!sasl_xoauth2::TokenStore::Create(log.get(), s_password));

  // A window as long as the token lifetime would refresh on every connection.
  SetPasswordToTokenFile(R"({"refresh_token": "r", "refresh_window": "3600"})");
  TEST_ASSERT(!sasl_xoauth2::TokenStore::Create(log.get(), s_password));
  return true;
}

// Another process refreshed (and rewrote) the token file after this one read
// it: this one picks up that token instead of requesting another.
bool TestUsesTokenRefreshedByOtherProcess() {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  FakeTokenEndpoint endpoint;
  endpoint.Install();

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);

  {
    std::ofstream f(s_password);
    f << R"({"access_token": "from_other_process", "refresh_token": "r2",
             "expiry": ")"
      << ExpiryIn(3600) << R"("})";
  }

  std::string token;
  TEST_ASSERT_OK(store->GetAccessToken(&token));
  TEST_ASSERT(token == "from_other_process");
  TEST_ASSERT(endpoint.calls == 0);
  return true;
}

bool TestMaxRefreshAttempts() {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  int calls = 0;
  sasl_xoauth2::SetHttpInterceptForTesting(
      [&calls](sasl_xoauth2::HttpPostOptions options) {
        calls++;
        *options.response = R"({"access_token": "access)" +
                            std::to_string(calls) + R"(", "expires_in": 3600})";
        *options.response_code = 200;
        return SASL_OK;
      });

  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  TEST_ASSERT_OK(store->Refresh());
  TEST_ASSERT_OK(store->Refresh());
  TEST_ASSERT(store->Refresh() != SASL_OK);
  TEST_ASSERT(calls == 2);
  return true;
}

bool TestErrorResponse() {
  PrintTestName(__func__);
  SetPasswordToExpiredToken();
  FakeTokenEndpoint endpoint;
  endpoint.response_code = 400;
  endpoint.response =
      R"({"error": "invalid_grant", "error_description": "AADSTS70000: The provided value for the 'refresh_token' is not valid.", "error_codes": [70000]})";
  endpoint.Install();

  const std::string before = ReadFile(s_password);
  auto log = sasl_xoauth2::Log::Create();
  auto store = sasl_xoauth2::TokenStore::Create(log.get(), s_password);
  TEST_ASSERT(store != nullptr);
  std::string token;
  TEST_ASSERT(store->GetAccessToken(&token) == SASL_BADPROT);
  // A failed refresh leaves the token file alone.
  TEST_ASSERT(ReadFile(s_password) == before);
  return true;
}

bool TestControlCharacterInUserRejected(sasl_client_plug_t plug) {
  PrintTestName(__func__);
  SetPasswordToTokenFile(
      TokenFileExpiringIn(3600, R"("user": "evil\u0001auth=Bearer x",)"));
  sasl_xoauth2::SetHttpInterceptForTesting(&DefaultHttpIntercept);

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackAll;
  utils.malloc = &FakeMalloc;

  void *context = nullptr;
  TEST_ASSERT_OK(plug.mech_new(nullptr, nullptr, &context));
  PlugCleanup _(&utils, plug, context);

  sasl_client_params_t params = {};
  params.utils = &utils;
  params.canon_user = &FakeCanonUser;

  const char *to_server = nullptr;
  unsigned int to_server_len = 0;
  sasl_out_params_t out_params = {};

  TEST_ASSERT(plug.mech_step(context, &params, nullptr, 0, nullptr, &to_server,
                             &to_server_len, &out_params) != SASL_OK);
  TEST_ASSERT(to_server_len == 0);
  return true;
}

int main(int argc, char **argv) {
  sasl_xoauth2::EnableLoggingForTesting();
  TEST_ABORT(TestRedactSecret());
  TEST_ABORT(TestEscapeForLog());

  Json::Value config;
  config["client_id"] = "dummy client id";
  config["client_secret"] = "dummy client secret";
  sasl_xoauth2::Config::EnableLoggingToStderr();
  TEST_ASSERT_OK(sasl_xoauth2::Config::InitForTesting(config));

  int version = 0;
  sasl_client_plug_t *plug_list = nullptr;
  int plug_count = 0;

  sasl_utils_t utils = {};
  utils.free = &FakeFree;
  utils.getcallback = &FakeGetCallbackNone;
  utils.malloc = &FakeMalloc;

  TEST_ABORT(sasl_client_plug_init(&utils, SASL_CLIENT_PLUG_VERSION, &version,
                                   &plug_list, &plug_count) == SASL_OK);
  fprintf(stderr,
          "INIT: sasl_client_plug_init returned version=%d, plug_count=%d\n",
          version, plug_count);
  TEST_ABORT(plug_count == 1);

  sasl_client_plug_t plug = *plug_list;
  fprintf(stderr, "INIT: module name: %s\n", plug.mech_name);

  TEST_ABORT(TestWithPrompts(plug));
  TEST_ABORT(TestWithoutPrompts(plug));
  TEST_ABORT(TestWithCallbacks(plug));
  TEST_ABORT(TestWithExpiryAfter2038(plug));
  TEST_ABORT(TestWithCallbacksAndUserOverride(plug));
  TEST_ABORT(TestWithCallbacksAndOtherOverrides(plug));
  TEST_ABORT(TestWithPermanentError(plug));
  TEST_ABORT(TestWithTokenExpiredError(plug));
  TEST_ABORT(TestPreemptiveTokenRefresh(plug));
  TEST_ABORT(TestFailedPreemptiveTokenRefresh(plug));
  TEST_ABORT(TestFormUrlEncode());
  TEST_ABORT(TestRefreshWindowFromConfig());
  TEST_ABORT(TestLegacyZeroRefreshWindowIgnored());
  TEST_ABORT(TestRefreshWindowOverrideInTokenFile());
  TEST_ABORT(TestTokenFilePermissionsKept());
  TEST_ABORT(TestRequestIsFormEncoded());
  TEST_ABORT(TestRotatedRefreshTokenStored());
  TEST_ABORT(TestClientCredentialsGrant(plug));
  TEST_ABORT(TestClientCredentialsWithoutScopeFails());
  TEST_ABORT(TestInvalidTokenFilesRejected());
  TEST_ABORT(TestUsesTokenRefreshedByOtherProcess());
  TEST_ABORT(TestMaxRefreshAttempts());
  TEST_ABORT(TestErrorResponse());
  TEST_ABORT(TestControlCharacterInUserRejected(plug));

  Cleanup();
  fprintf(stderr, "\nALL TESTS PASS.\n");

  return 0;
}
