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

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>

#include <algorithm>
#include <memory>

namespace sasl_xoauth2 {

namespace {

Log::Options s_default_options = Log::OPTIONS_NONE;
Log::Target s_default_target = Log::TARGET_SYSLOG;

std::string Now() {
  time_t t = time(nullptr);
  char time_str[32];
  tm local_time = {};
  localtime_r(&t, &local_time);
  strftime(time_str, sizeof(time_str), "%F %T", &local_time);
  return std::string(time_str);
}

class NoOpLogger : public LogImpl {
 public:
  NoOpLogger() = default;
  ~NoOpLogger() override = default;

  void WriteLine(const std::string &line) override {}
};

class SysLogLogger : public LogImpl {
 public:
  SysLogLogger() = default;
  ~SysLogLogger() override = default;

  void WriteLine(const std::string &line) override {
    syslog(LOG_WARNING, "[sasl-xoauth2] %s", line.c_str());
  }
};

class StdErrLogger : public LogImpl {
 public:
  StdErrLogger() = default;
  ~StdErrLogger() override = default;

  void WriteLine(const std::string &line) override {
    fprintf(stderr, "%s\n", line.c_str());
  }
};

std::unique_ptr<LogImpl> CreateLogImpl(Log::Target target) {
  switch (target) {
    case Log::TARGET_NONE:
      return std::make_unique<NoOpLogger>();
    case Log::TARGET_SYSLOG:
      return std::make_unique<SysLogLogger>();
    case Log::TARGET_STDERR:
      return std::make_unique<StdErrLogger>();
    default:
      exit(1);
  };
}

}  // namespace

std::string RedactSecret(const std::string &secret) {
  if (secret.empty()) return "<empty>";
  return "<redacted, " + std::to_string(secret.size()) + " bytes>";
}

std::string EscapeForLog(const std::string &value, size_t max_length) {
  std::string out;
  out.reserve(std::min(value.size(), max_length));
  for (const unsigned char c : value) {
    if (out.size() >= max_length) {
      out += "...<" + std::to_string(value.size()) + " bytes>";
      break;
    }
    if (c < 0x20 || c == 0x7f || c == '\\') {
      char buf[8];
      snprintf(buf, sizeof(buf), "\\x%02x", c);
      out += buf;
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  return out;
}

void EnableLoggingForTesting() {
  s_default_options = Log::OPTIONS_IMMEDIATE;
  s_default_target = Log::TARGET_STDERR;
}

std::unique_ptr<Log> Log::Create(Options options, Target target) {
  options = static_cast<Options>(options | s_default_options);
  if (target == TARGET_DEFAULT) target = s_default_target;
  return std::unique_ptr<Log>(
      new Log(CreateLogImpl(target), options, target == TARGET_NONE));
}

Log::~Log() {
  if (options_ & OPTIONS_FLUSH_ON_DESTROY) Flush();
}

namespace {

std::string FormatV(const char *fmt, va_list args) {
  va_list copy;
  va_copy(copy, args);
  const int buf_len = vsnprintf(nullptr, 0, fmt, copy);
  va_end(copy);
  if (buf_len < 0) return {};

  // +1 for the trailing \0, which is not part of the line.
  std::vector<char> buf(buf_len + 1);
  vsnprintf(buf.data(), buf.size(), fmt, args);
  return std::string(buf.data(), buf_len);
}

}  // namespace

void Log::Write(const char *fmt, ...) {
  if (discard_) return;
  va_list args;
  va_start(args, fmt);
  std::string line = FormatV(fmt, args);
  va_end(args);
  WriteLine(std::move(line), /*is_error=*/false);
}

void Log::Error(const char *fmt, ...) {
  if (discard_) return;
  va_list args;
  va_start(args, fmt);
  std::string line = FormatV(fmt, args);
  va_end(args);
  WriteLine(std::move(line), /*is_error=*/true);
}

void Log::WriteLine(std::string line, bool is_error) {
  if (is_error) error_summary_ = line;
  if (options_ & OPTIONS_IMMEDIATE) {
    impl_->WriteLine(line);
  } else {
    lines_.push_back(Now() + ": " + line);
  }
}

void Log::Flush() {
  if (lines_.empty()) return;
  const std::string prefix =
      std::string("auth failed (sasl-xoauth2 ") + SASL_XOAUTH2_VERSION + ")";
  if (options_ & OPTIONS_FULL_TRACE_ON_FAILURE) {
    impl_->WriteLine(prefix + ":");
    for (const auto &line : lines_) impl_->WriteLine("  " + line);
  } else {
    if (summary_.empty()) summary_ = lines_.back();
    impl_->WriteLine(prefix + ": " + summary_);
    if (lines_.size() > 1) {
      impl_->WriteLine("set log_full_trace_on_failure to see full " +
                       std::to_string(lines_.size()) + " line(s) of tracing.");
    }
  }
}

void Log::SetFlushOnDestroy() {
  options_ = static_cast<Options>(options_ | OPTIONS_FLUSH_ON_DESTROY);
  if (!error_summary_.empty()) {
    summary_ = error_summary_;
  } else if (!lines_.empty()) {
    summary_ = lines_.back();
  }
}

}  // namespace sasl_xoauth2
