/*
 * Copyright 2026 The sasl-xoauth2 Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SASL_XOAUTH2_CLIENT_ASSERTION_H
#define SASL_XOAUTH2_CLIENT_ASSERTION_H

#include <time.h>

#include <string>

namespace sasl_xoauth2 {

// Lifetime of a client assertion. Microsoft asks to keep it short (5-10
// minutes); it is only used for the one token request it is made for.
constexpr int kClientAssertionLifetimeSec = 300;

constexpr char kClientAssertionType[] =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// Creates a signed JWT that authenticates |client_id| to |audience| (the token
// endpoint) with a certificate instead of a client secret, as described in
// "Microsoft identity platform application authentication certificate
// credentials": PS256 signature, "x5t#S256" certificate thumbprint, and the
// claims aud, iss, sub, jti, nbf, iat and exp.
//
// |certificate_file| is a PEM file with the X.509 certificate registered for
// the application; |private_key_file| a PEM file with its (unencrypted) RSA
// private key. Both may be the same file. Returns false and sets |error| on
// failure.
bool CreateClientAssertion(const std::string &certificate_file,
                           const std::string &private_key_file,
                           const std::string &client_id,
                           const std::string &audience, time_t now,
                           std::string *assertion, std::string *error);

// The base64url (RFC 4648, section 5) encoding of |data|, without padding.
std::string Base64UrlEncode(const std::string &data);

}  // namespace sasl_xoauth2

#endif  // SASL_XOAUTH2_CLIENT_ASSERTION_H
