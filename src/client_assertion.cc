// Copyright 2026 The sasl-xoauth2 Authors
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

#include "client_assertion.h"

#include <json/json.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>

#include <memory>
#include <vector>

namespace sasl_xoauth2 {

namespace {

struct FileCloser {
  void operator()(FILE *f) const { fclose(f); }
};
struct X509Deleter {
  void operator()(X509 *x) const { X509_free(x); }
};
struct PKeyDeleter {
  void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); }
};
struct MdCtxDeleter {
  void operator()(EVP_MD_CTX *c) const { EVP_MD_CTX_free(c); }
};

std::string OpenSslError(const std::string &what) {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  if (code == 0) return what;
  char buf[256];
  ERR_error_string_n(code, buf, sizeof(buf));
  return what + ": " + buf;
}

std::unique_ptr<FILE, FileCloser> OpenPem(const std::string &path,
                                          std::string *error) {
  std::unique_ptr<FILE, FileCloser> f(fopen(path.c_str(), "re"));
  if (!f) *error = "unable to open " + path;
  return f;
}

std::string RandomUuid() {
  unsigned char b[16];
  if (RAND_bytes(b, sizeof(b)) != 1) return {};
  b[6] = (b[6] & 0x0f) | 0x40;  // Version 4.
  b[8] = (b[8] & 0x3f) | 0x80;  // RFC 4122 variant.
  char out[37];
  snprintf(out, sizeof(out),
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x"
           "%02x",
           b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10],
           b[11], b[12], b[13], b[14], b[15]);
  return out;
}

std::string CompactJson(const Json::Value &value) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "";
  return Json::writeString(builder, value);
}

}  // namespace

std::string Base64UrlEncode(const std::string &data) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 2 < data.size(); i += 3) {
    const unsigned v = (static_cast<unsigned char>(data[i]) << 16) |
                       (static_cast<unsigned char>(data[i + 1]) << 8) |
                       static_cast<unsigned char>(data[i + 2]);
    out.push_back(kAlphabet[(v >> 18) & 0x3f]);
    out.push_back(kAlphabet[(v >> 12) & 0x3f]);
    out.push_back(kAlphabet[(v >> 6) & 0x3f]);
    out.push_back(kAlphabet[v & 0x3f]);
  }
  if (i + 1 == data.size()) {
    const unsigned v = static_cast<unsigned char>(data[i]) << 16;
    out.push_back(kAlphabet[(v >> 18) & 0x3f]);
    out.push_back(kAlphabet[(v >> 12) & 0x3f]);
  } else if (i + 2 == data.size()) {
    const unsigned v = (static_cast<unsigned char>(data[i]) << 16) |
                       (static_cast<unsigned char>(data[i + 1]) << 8);
    out.push_back(kAlphabet[(v >> 18) & 0x3f]);
    out.push_back(kAlphabet[(v >> 12) & 0x3f]);
    out.push_back(kAlphabet[(v >> 6) & 0x3f]);
  }
  return out;
}

bool CreateClientAssertion(const std::string &certificate_file,
                           const std::string &private_key_file,
                           const std::string &client_id,
                           const std::string &audience, time_t now,
                           std::string *assertion, std::string *error) {
  ERR_clear_error();

  // The certificate only provides the thumbprint that tells Entra ID which of
  // the application's certificates signed the assertion.
  auto cert_file = OpenPem(certificate_file, error);
  if (!cert_file) return false;
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_X509(cert_file.get(), nullptr, nullptr, nullptr));
  if (!cert) {
    *error = OpenSslError("no PEM certificate in " + certificate_file);
    return false;
  }

  auto key_file = OpenPem(private_key_file, error);
  if (!key_file) return false;
  // No passphrase callback: the key has to be readable unattended. A
  // passphrase-protected key fails here instead of prompting.
  static char kNoPassphrase[] = "";
  std::unique_ptr<EVP_PKEY, PKeyDeleter> key(
      PEM_read_PrivateKey(key_file.get(), nullptr, nullptr, kNoPassphrase));
  if (!key) {
    *error =
        OpenSslError("no unencrypted PEM private key in " + private_key_file);
    return false;
  }
  if (EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA) {
    *error = "the private key in " + private_key_file +
             " is not an RSA key (PS256 needs RSA)";
    return false;
  }
  if (X509_check_private_key(cert.get(), key.get()) != 1) {
    ERR_clear_error();
    *error = "the private key in " + private_key_file +
             " does not belong to the certificate in " + certificate_file;
    return false;
  }

  unsigned char thumbprint[EVP_MAX_MD_SIZE];
  unsigned int thumbprint_len = 0;
  if (X509_digest(cert.get(), EVP_sha256(), thumbprint, &thumbprint_len) != 1) {
    *error = OpenSslError("unable to compute certificate thumbprint");
    return false;
  }

  const std::string jti = RandomUuid();
  if (jti.empty()) {
    *error = OpenSslError("unable to generate random jti");
    return false;
  }

  Json::Value header;
  header["alg"] = "PS256";
  header["typ"] = "JWT";
  header["x5t#S256"] = Base64UrlEncode(
      std::string(reinterpret_cast<char *>(thumbprint), thumbprint_len));

  Json::Value claims;
  claims["aud"] = audience;
  claims["iss"] = client_id;
  claims["sub"] = client_id;
  claims["jti"] = jti;
  claims["nbf"] = static_cast<Json::Int64>(now);
  claims["iat"] = static_cast<Json::Int64>(now);
  claims["exp"] = static_cast<Json::Int64>(now + kClientAssertionLifetimeSec);

  const std::string signing_input = Base64UrlEncode(CompactJson(header)) + "." +
                                    Base64UrlEncode(CompactJson(claims));

  std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX *pctx = nullptr;  // Owned by |ctx|.
  if (!ctx ||
      EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key.get()) !=
          1 ||
      EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
      // RFC 7518, section 3.5: the salt is as long as the hash.
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
    *error = OpenSslError("unable to set up PS256 signing");
    return false;
  }
  size_t signature_len = 0;
  if (EVP_DigestSign(
          ctx.get(), nullptr, &signature_len,
          reinterpret_cast<const unsigned char *>(signing_input.data()),
          signing_input.size()) != 1) {
    *error = OpenSslError("unable to sign client assertion");
    return false;
  }
  std::vector<unsigned char> signature(signature_len);
  if (EVP_DigestSign(
          ctx.get(), signature.data(), &signature_len,
          reinterpret_cast<const unsigned char *>(signing_input.data()),
          signing_input.size()) != 1) {
    *error = OpenSslError("unable to sign client assertion");
    return false;
  }

  *assertion = signing_input + "." +
               Base64UrlEncode(std::string(
                   reinterpret_cast<char *>(signature.data()), signature_len));
  return true;
}

}  // namespace sasl_xoauth2
