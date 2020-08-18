Unthread
========

Unthread is an implmentation of POSIX threads designed for fuzzing and debugging of concurrent
programs. Unthread is:

- **deterministic**: Identical seeds will result in identical threading schedules.
- **fuzzable**: Unthread can be used for instrumented fuzzing of threaded code, although the
  coverage-based heuristics used by most fuzzers are likely inefficient for this.
- **strict**: Unthread only implementes the minimum required by the spec.
- **instant**: Timed locks do not wait for wall-time to pass before a lock is acquired/times out.

With some caveats:

- **Not parallel**: Unthread does not use any actual hardware threading. All threads run on a single
  core.
- **No preemption**: Control is only transfered at "yield points", which includes most pthread
  functions. This means that code cannot depend on other threads making progress by eg. waiting in a
  loop until some condition is met. `pthread_yield` can be inserted in these cases to provide a
  yield point.
- **Non-conformance**: Not being a "real" pthreads implementation that integrates with the system
  means some parts of the POSIX spec are difficult/impossible to implement:
  - Only `pthread_cond_timedwait`, `pthread_cond_wait`, `pthread_join`, and `pthread_testcancel` are
    cancellation points.
  - Process shared objects are not supported (`PTHREAD_PROCESS_SHARED`).
  - Signal handling is not supported.
- **Glibc only**: Only Glibc is supported at the moment. PR's welcome!
- **Incomplete**: Unthread is a work in progress and some pthread features have not been implemented
  yet:
  - Robust mutexes.
  - Semaphores.

Example
-------

Here is a example from the Unthread test suite of a program with a race condition:

```c
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

static int val = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* incr(void* arg) {
    int v;
    
    pthread_mutex_lock(&mutex);
    v = val;
    pthread_mutex_unlock(&mutex);

    pthread_mutex_lock(&mutex);
    val = v + 1;
    pthread_mutex_unlock(&mutex);

    return NULL;
}

int main() {
    pthread_t a,b;
    pthread_create(&a, NULL, incr, NULL);
    pthread_create(&b, NULL, incr, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("%d", val);
    
    return 0;
}
```

This program has no data-races as all access to `val` is protected behind a mutex. But it *does*
have a scheduling-based race condition as the final value it outputs depends on the scheduling
order. For this particular example and my particular machine/OS, this non-determinism does occur
under standard pthreads given enough executions:

```console
$ make bin/mutex-pthread
$ seq 1000 | xargs -i bin/mutex-pthread
2222222222222222222222222222222222222212222222222222222122222222222222222222222222222222222222222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
2222222222212222222222222222222222222222222222222222222222222222222222222122222222222222222222222222
2222222221222222222222222222222222222222222222222222222222222222222222222222222222222222222221222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
2222222222222222222222222222221222222222222222222222222222222222221222222222222222222222222222222222
2222222222222222222222222222222222222222222222222222222222222222222222222222222122222222222222222222
```

This is not true in the general case. It might be that a race condition only shows under some
special conditions, like high load, a certain os, or certain hardware. To make matters worse,
debuggers can affect timings such that race conditions disappear. Unthread allows us to test this in
a structured way instead of just hoping that we are able to trigger non-deterministic behavior.

Let us say that the expected value is 2 in the above example is 2 and the buggy value is 1. We can
test this using the `unthread-fuzz` utility. By default, this program just executes the program with
different seeds until it returns with a non-zero return code, in which case the failing seed is
printed to standard out.

```console
$ make bin/mutex
$ make bin/unthread-fuzz
$ bin/unthread-fuzz sh -c '[ $(bin/mutex) -eq "2" ]'
f503e38ee865d082f5773198fb24df71
```

It found a failing seed! We can execute the program with the given seed and get the exact same
result each time:

```console
$ UNTHREAD_SEED=f503e38ee865d082f5773198fb24df71 bin/mutex
1
```

The program can then be debugged with standard debuggers like GDB or similar.

Usage
-----

Build Unthread by running `make` in this dir (or add it to your build). Then link to Unthread
instead of pthread and use the Unthread include dir. Eg. instead of `cc main.c -lpthread` do
`cc main.c -Lunthread/bin/unthread.o -I unthread/include`. Optionally also include the
`include-util` dir.

The thread schedule (i.e. the sequence in which threads yield to each other) can be defined in the
following ways:
- By setting the environment variable `UNTHREAD_SEED` to a 32-character hexadecimal string. Unthread
  will use this to seed a PRNG that then picks the thread schedule.
- By setting the environment variable `UNTHREAD_FILE` to point to a file that will be used as
  entropy source for the thread schedule. This could for example be random noise to get a random
  execution (much like setting `UNTHREAD_SEED`) or it could be the result of a instrumented fuzzing
  process. When using file schedule input, Unthread will exit if the entropy file is depleted.
- By setting neither, in which case the standard input is used as an entropy source like it would be
  from a file.

Using Unthread with libraries that themselves link to pthread will need to be rebuilt with Unthread.
Good luck. :)

Configuration
-------------

Unthread can be configured by setting the following environment variables:

| Environment variable | Use                              |
|----------------------|----------------------------------|
| UNTHREAD_SEED        | Seed for thread schedule         |
| UNTHREAD_FILE        | Entropy file for thread schedule |
| UNTHREAD_VERBOSE     | `true` for verbose logging       |
| UNTHREAD_RET_OFFSET  | Return code offset               |

Return codes
------------

Unthread may stop the application under a number of conditions:

| Retcode |                                                |
|---------|------------------------------------------------|
| 40      | The thread schedule entropy was exhausted      |
| 41      | All threads have become deadlocked             |
| 42      | An illegal operation was performed             |
| 43      | Allocation failure                             |
| 44      | Misc. failure (usually if a system call fails) |
| 45      | Failure while reading from IO                  |
| 46      | An unsupported operation was performed         |

In case that the retcode clashes with the retcode of the application, the default retcode offset of
40 can be changed by setting the `UNTHREAD_RET_OFFSET` environment variable.

Testing
-------

The Unthread test runner requires Python 3 to be installed.

Unthread is tested by the Unthread tests in the `test-src` dir and a set of tests from the POSIX
Test Suite project in the `posixtestsuite`. See the
[POSIX Test Suite project site](https://sourceforge.net/projects/posixtest) for more information on
the POSIX Test Suite.

Unthread tests in the `test-src` directory are examples of non-deterministic pthread programs that
are deterministic in Unthread with a given seed. The tests contains a spec containing all the
possible outcomes of running the test, and a list of seeds in a seperate `.seeds` file. These seeds
*must* cover all the possible outcomes or the test will fail. When emodifying Unthread, it may be
necessary to generate new seeds by executing `UNTHREAD_GEN=true make test`.

The above will only generate the minimum number of seeds to cover the outcomes. Additional fuzzing
can be done by executing `UNTHREAD_ITER=N make unthread-fuzz` where `N` is the number of iterations
to fuzz.

See also
--------

[rr](https://rr-project.org/), a gdb debugger with deterministic replay.
