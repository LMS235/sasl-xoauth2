#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <sasl/sasl.h>
#include <string.h>
#include <unistd.h>

#include <vector>

#include "config.h"
#include "log.h"
#include "token_store.h"

namespace {

// Exit codes, for monitoring: whether a failure needs someone to act.
constexpr int kExitOk = 0;
constexpr int kExitTransient = 1;  // e.g. network problem, provider outage.
constexpr int kExitPermanent = 2;  // e.g. invalid config, rejected token.

struct Options {
  std::string config_path;
  std::string token_path;
  bool update = false;
  bool help = false;
};

bool TryParseCommandLine(int argc, char **argv, Options *out) {
  const char *kShortOptions = "c:r:uvVh";
  const option kLongOptions[] = {{"config", required_argument, nullptr, 'c'},
                                 {"token", required_argument, nullptr, 'r'},
                                 {"update", no_argument, nullptr, 'u'},
                                 {"version", no_argument, nullptr, 'V'},
                                 {"help", no_argument, nullptr, 'h'},
                                 {nullptr, 0, nullptr, 0}};

  while (true) {
    int opt = getopt_long(argc, argv, kShortOptions, kLongOptions, nullptr);
    if (opt == -1) break;

    switch (opt) {
      case 'c':
        out->config_path = optarg;
        break;

      case 'r':
        out->token_path = optarg;
        break;

      case 'u':
        out->update = true;
        break;

      case 'h':
        out->help = true;
        break;

      case 'v':
      case 'V':
        printf("sasl-xoauth2 %s\n", SASL_XOAUTH2_VERSION);
        exit(kExitOk);

      default:
        return false;
    }
  }

  return !out->update || !out->token_path.empty();
}

void PrintUsage(const std::string &base_name) {
  fprintf(stderr,
          "Usage: %s [options]\n\n"
          "Options:\n"
          "  -c, --config=<file>  use <file> for configuration rather than\n"
          "                       system default\n"
          "  -r, --token=<file>   attempt to request a token from the OAuth\n"
          "                       provider using the token file <file> (which\n"
          "                       is not modified, unless --update is given)\n"
          "  -u, --update         with --token: store the new token in the\n"
          "                       token file (also renews a rotating refresh\n"
          "                       token, e.g. Microsoft's); for a scheduled\n"
          "                       daily refresh\n"
          "  -V, -v, --version    print the version and exit\n"
          "  -h, --help           print this help and exit\n\n"
          "Exit status: 0 on success, 1 on a transient failure (e.g. network\n"
          "problem or provider outage), 2 on a failure that needs action\n"
          "(e.g. invalid configuration, rejected token, unwritable token\n"
          "directory).\n",
          base_name.c_str());
}

Options ParseCommandLine(int argc, char **argv) {
  const std::string base_name = basename(argv[0]);
  Options parsed_options;

  if (!TryParseCommandLine(argc, argv, &parsed_options)) {
    PrintUsage(base_name);
    exit(kExitPermanent);
  }
  if (parsed_options.help) {
    PrintUsage(base_name);
    exit(kExitOk);
  }

  return parsed_options;
}

// The plugin replaces the token file by writing a new file next to it and
// takes a lock file there, so the directory must be writable.
bool CheckTokenDirectoryWritable(const std::string &token_path) {
  std::vector<char> buf(token_path.begin(), token_path.end());
  buf.push_back('\0');
  const std::string dir = dirname(buf.data());
  if (access(dir.c_str(), W_OK) == 0) return true;
  printf(
      "Token directory %s is not writable for this user (%s); sasl-xoauth2 "
      "could not store refreshed tokens. Check owner and permissions (and, "
      "on systemd, ReadWritePaths for the mail system).\n",
      dir.c_str(), strerror(errno));
  return false;
}

}  // namespace

int main(int argc, char **argv) {
  const Options options = ParseCommandLine(argc, argv);

  sasl_xoauth2::Config::EnableLoggingToStderr();
  if (sasl_xoauth2::Config::Init(options.config_path) != SASL_OK) {
    printf("Config check failed.\n");
    return kExitPermanent;
  }
  printf("Config check passed.\n");

  if (!options.token_path.empty()) {
    auto logger = sasl_xoauth2::Log::Create(
        sasl_xoauth2::Log::OPTIONS_FULL_TRACE_ON_FAILURE,
        sasl_xoauth2::Log::TARGET_STDERR);
    auto token_store =
        sasl_xoauth2::TokenStore::Create(logger.get(), options.token_path,
                                         /*enable_updates=*/options.update);
    if (!token_store) {
      logger->Flush();
      printf("Failed to read token.\n");
      return kExitPermanent;
    }
    if (token_store->Refresh() != SASL_OK) {
      logger->Flush();
      printf("Token refresh failed.\n");
      return token_store->last_error_permanent() ? kExitPermanent
                                                 : kExitTransient;
    }
    if (options.update && token_store->last_write_failed()) {
      logger->Flush();
      printf(
          "Token refresh succeeded, but the token file could not be "
          "updated.\n");
      CheckTokenDirectoryWritable(options.token_path);
      return kExitPermanent;
    }
    printf(options.update ? "Token refresh succeeded; token file updated.\n"
                          : "Token refresh succeeded.\n");
    if (!CheckTokenDirectoryWritable(options.token_path)) return kExitPermanent;
  }

  return kExitOk;
}
