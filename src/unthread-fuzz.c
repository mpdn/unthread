#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, message, ...)                   \
  do {                                              \
    if (!(cond)) {                                  \
      fprintf(stderr, message "\n", ##__VA_ARGS__); \
      return -1;                                    \
    }                                               \
  } while (false)

struct process {
  pid_t pid;
  bool generated;
  char seed_str[32];
};

int main(int argc, char *argv[]) {
  static struct option long_options[] = {
      {"parallelism", optional_argument, NULL, 'p'},
      {"seeds", required_argument, NULL, 's'},
      {"fuzz", optional_argument, NULL, 'f'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };

  bool parsing = true;
  bool help = false;
  unsigned long parallelism = 1;
  bool fuzz = false;
  unsigned long fuzz_iterations = -1;

  char *seeds_path = NULL;
  int opt, option_index = 0;
  char *endptr;
  while (parsing && (opt = getopt_long(argc, argv, ":p::s:f::h", long_options,
                                       &option_index)) != -1) {
    switch (opt) {
      case 'p':
        parallelism = get_nprocs();

        if (optarg != NULL) {
          unsigned long parsed = strtoul(optarg, &endptr, 10);

          if (*endptr == 0) {
            parallelism = parsed;
          } else {
            // Not a number, must be start of command
            goto command;
          }
        }
        break;
      case 's':
        seeds_path = optarg;
        break;
      case 'f':
        fuzz = true;
        if (optarg != NULL) {
          unsigned long parsed = strtoul(optarg, &endptr, 10);

          if (*endptr == 0) {
            fuzz_iterations = parsed;
          } else {
            // Not a number, must be start of command
            goto command;
          }
        }
        break;
      case 'h':
        help = true;
        break;
      default:
        CHECK(false, "Unexpected value from getopt_long: %d", opt);
        break;
      case '?':
      command:
        // Start of a command - unparse the last argument and stop parsing.
        parsing = false;
        option_index--;
        optind--;
        break;
    }
  }

  int child_args_start = optind - 1;

  int child_argc = argc - child_args_start;
  if (child_argc <= 0) {
    help = true;
  }

  if (help) {
    // clang-format off
    printf(
      "Usage: %s [-pfsh] <command>\n"
      "Test a program with different Unthread seeds\n"
      "\n"
      "  -p, --parallelism [<n>]  Number of processes to execute in parallel. If no\n"
      "                           value is set, uses the number of machine cores.\n"
      "  -f, --fuzz [<n>]         Run n iterations of random seeds. If number of\n"
      "                           iterations is not set, will continue until\n"
      "                           interrupted.\n"
      "  -s, --seeds <path>       Path to seeds file. The program will be tested with\n"
      "                           the seeds found in this file.\n"
      "  -h, --help               Show this screen.\n"
      "\n"
      "If both --seeds and --fuzz are specified, the program will first be tested with\n"
      "the seeds in the seeds file, and afterwards tested with random seeds. If a\n"
      "failing random seed is found, it will be added to the end of the seeds file.\n",
      basename(argv[0])
    );
    // clang-format on

    return 0;
  }

  fuzz |= seeds_path == NULL;

  FILE *noise = fopen("/dev/urandom", "r");
  FILE *seeds = NULL;

  if (seeds_path != NULL) {
    seeds = fopen(seeds_path, fuzz ? "a+" : "r");
    CHECK(seeds != NULL, "Failed opening seeds file: %s", strerror(errno));
    CHECK(fseek(seeds, 0, SEEK_SET) == 0,
          "Failed seeking to beginning of seeds file: %s", strerror(errno));
  }

  struct process *processes = malloc(parallelism * sizeof(struct process));
  CHECK(processes != NULL, "Failed allocating process list");

  char **child_argv = calloc(child_argc + 1, sizeof(char *));
  CHECK(child_argv != NULL, "Failed allocating child argument list");

  memcpy(child_argv, argv + child_args_start, child_argc * sizeof(char *));

  posix_spawn_file_actions_t action;
  CHECK(posix_spawn_file_actions_init(&action) == 0 &&
            posix_spawn_file_actions_addopen(&action, STDOUT_FILENO,
                                             "/dev/null", O_WRONLY, 0) == 0,
        "Failed setting up spawn actions: %s", strerror(errno));

  unsigned long running = 0;

  while (fuzz_iterations == -1 || fuzz_iterations > 0) {
    while (running < parallelism) {
      struct process process;

      if (seeds != NULL && fscanf(seeds, "%32s\n", process.seed_str) > 0) {
        process.generated = false;
      } else if (seeds == NULL || feof(seeds)) {
        if (fuzz && (fuzz_iterations == -1 || fuzz_iterations > 0)) {
          if (fuzz_iterations != -1) {
            fuzz_iterations--;
          }

          char seed[16];
          CHECK(fread(&seed, sizeof(seed), 1, noise),
                "Failed reading random seed: %s", strerror(errno));
          process.generated = true;

          for (int i = 0; i < sizeof(seed) * 2; i++) {
            char c = (seed[i / 2] >> ((i % 2) * 4)) & 0xf;
            process.seed_str[i] = c < 10 ? '0' + c : 'a' + c - 10;
          }
        } else {
          break;
        }
      } else {
        CHECK(ferror(seeds), "Failed reading seeds: %s", strerror(errno));
        CHECK(false, "Invalid seeds format");
      }

      char seed_prefix[] = "UNTHREAD_SEED=";
      char seed_str[sizeof(seed_prefix) + sizeof(process.seed_str)];
      sprintf(seed_str, "%s%32s", seed_prefix, process.seed_str);

      CHECK(posix_spawnp(&process.pid, child_argv[0], &action, NULL, child_argv,
                         (char *[]){seed_str, NULL}) == 0,
            "Failed spawning process: %s", strerror(errno));

      processes[running++] = process;
    }

    int status;
    pid_t pid = wait(&status);

    for (size_t i = 0; i < running; i++) {
      if (processes[i].pid == pid) {
        struct process process = processes[i];
        processes[i] = processes[--running];

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
          printf("%32s\n", process.seed_str);

          if (seeds != NULL && process.generated) {
            CHECK(fprintf(seeds, "%32s\n", process.seed_str) == 0,
                  "Failed writing seed to seed file: %s", strerror(errno));
            CHECK(fclose(seeds), "Failed closing seeds file: %s",
                  strerror(errno));
          }

          for (int j = 0; j < running; j++) {
            // Just continue if killing children fails
            kill(processes[j].pid, SIGTERM);
          }

          return 1;
        }
        break;
      }
    }
  }

  return 0;
}