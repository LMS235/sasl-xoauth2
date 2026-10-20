/*
 * Copyright 2020 Google LLC
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

#ifndef SASL_XOAUTH2_LOG_H
#define SASL_XOAUTH2_LOG_H

#include <memory>
#include <string>
#include <vector>

namespace sasl_xoauth2 {

void EnableLoggingForTesting();

// Stand-in for a secret (token, client secret) in log lines: its length only,
// so a trace still shows whether a value was present without revealing it.
std::string RedactSecret(const std::string &secret);

// Escapes control characters (as \xNN) in values that come from outside, so
// they cannot forge or split log lines, and cuts them to |max_length| bytes.
std::string EscapeForLog(const std::string &value, size_t max_length = 2048);

// Log implementation interface, not for direct use.
class LogImpl {
 public:
  virtual ~LogImpl() = default;

  virtual void WriteLine(const std::string &line) = 0;
};

class Log {
 public:
  enum Options {
    OPTIONS_NONE = 0,
    OPTIONS_IMMEDIATE = 1,
    OPTIONS_FULL_TRACE_ON_FAILURE = 2,
    OPTIONS_FLUSH_ON_DESTROY = 4,
  };

  enum Target {
    TARGET_DEFAULT = 0,
    TARGET_NONE = 1,
    TARGET_SYSLOG = 2,
    TARGET_STDERR = 3,
  };

  static std::unique_ptr<Log> Create(Options options = OPTIONS_NONE,
                                     Target target = TARGET_DEFAULT);

  ~Log();

  // printf-style; the attribute lets the compiler check arguments (this is a
  // member function, so argument 1 is the implicit |this|).
  void Write(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
  // Like Write(), but also makes the line the one-line summary logged when
  // authentication fails (unless a full trace is logged): the reason, not
  // merely the last step.
  void Error(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
  void Flush();
  void SetFlushOnDestroy();

 protected:
  Log(std::unique_ptr<LogImpl> impl, Options options, bool discard)
      : impl_(std::move(impl)), options_(options), discard_(discard) {}

 private:
  const std::unique_ptr<LogImpl> impl_;

  Options options_;
  // Nothing would ever be printed (TARGET_NONE), so skip formatting entirely.
  const bool discard_;
  void WriteLine(std::string line, bool is_error);

  std::string summary_;
  std::string error_summary_;
  std::vector<std::string> lines_;
};

}  // namespace sasl_xoauth2

#endif  // SASL_XOAUTH2_LOG_H
