CFLAGS=-std=gnu11 -Wall

TEST_SEED=bcf23e872718fb953d8b138d63098e2f

bin:
	mkdir -p bin

bin/unthread.o: src/unthread.c | bin
	$(CC) -c -o $@ $< $(CFLAGS) -g -I include

bin/%-pthread: test-src/%.c src/pthread.c include/pthread.h include/bits/pthreadtypes.h | bin
	$(CC) -o $@ $< $(CFLAGS) -g -pthread

bin/%: test-src/%.c bin/unthread.o include/pthread.h include/bits/pthreadtypes.h | bin
	$(CC) -o $@ $< bin/unthread.o $(CFLAGS) -I include -g

bin/%.test: test-src/%.c bin/% test-src/test.py | test-src/%.json
	test-src/test.py --src $< --bin bin/$* --cases test-src/$*.json > $@

test-src/%.json: test-src/%.c include/pthread.h test-src/test.py | bin/%
	test-src/test.py --src $< --bin bin/$* --cases $@ --gen

# Posix test suite rules

bin/posixtestsuite/conformance/interfaces/mmap/%: CFLAGS+=-lrt

bin/posixtestsuite/%: posixtestsuite/%.c $(wildcard posixtestsuite/%/*) bin/unthread.o
	@mkdir -p $$(dirname "$@")
	$(CC) -o $@ $< bin/unthread.o $(CFLAGS) -I include -I posixtestsuite/include -g

bin/posixtestsuite/%-pthread: posixtestsuite/%.c $(wildcard posixtestsuite/%/*)
	@mkdir -p $$(dirname "$@")
	$(CC) -o $@ $< $(CFLAGS) -lpthread -I posixtestsuite/include -g

bin/posixtestsuite/%.test: bin/posixtestsuite/%
	@echo posixtestsuite/$*.c
	UNTHREAD_SEED=$(TEST_SEED) UNTHREAD_VERBOSE=true bin/posixtestsuite/$* > $@

# We ignore a number of posixtestsuite tests - usually because either:
#  - They depend on preemption
#  - They depend on behavior not guaranteed by the spec
#  - They depend on signal handling
POSIX_TEST_SUITES_BLACKLIST=\
	posixtestsuite/conformance/interfaces/pthread_attr_setdetachstate/2-1.c      \
	posixtestsuite/conformance/interfaces/pthread_attr_setinheritsched/4-1.c     \
	posixtestsuite/conformance/interfaces/pthread_attr_setschedpolicy/4-1.c      \
	posixtestsuite/conformance/interfaces/pthread_attr_setscope/4-1.c            \
	posixtestsuite/conformance/interfaces/pthread_attr_setscope/5-1.c            \
	posixtestsuite/conformance/interfaces/pthread_condattr_destroy/4-1.c         \
	posixtestsuite/conformance/interfaces/pthread_condattr_setclock/1-3.c        \
	posixtestsuite/conformance/interfaces/pthread_create/2-1.c                   \
	posixtestsuite/conformance/interfaces/pthread_detach/4-2.c                   \
	posixtestsuite/conformance/interfaces/pthread_getschedparam/1-3.c            \
	posixtestsuite/conformance/interfaces/pthread_join/6-2.c                     \
	posixtestsuite/conformance/interfaces/pthread_kill/6-1.c                     \
	posixtestsuite/conformance/interfaces/pthread_mutex_getprioceiling/1-1.c     \
	posixtestsuite/conformance/interfaces/pthread_mutexattr_destroy/4-1.c        \
	posixtestsuite/conformance/interfaces/pthread_mutexattr_getprioceiling/1-1.c \
	posixtestsuite/conformance/interfaces/pthread_mutexattr_setprotocol/3-1.c    \
	posixtestsuite/conformance/interfaces/pthread_once/4-1.c                     \
	posixtestsuite/conformance/interfaces/pthread_rwlock_destroy/3-1.c           \
	posixtestsuite/conformance/interfaces/pthread_rwlock_unlock/4-1.c            \
	posixtestsuite/conformance/interfaces/pthread_rwlock_wrlock/3-1.c            \
	posixtestsuite/conformance/interfaces/pthread_setcancelstate/3-1.c           \
	posixtestsuite/conformance/interfaces/pthread_spin_destroy/3-1.c

POSIX_TEST_SUITES_ALL=$(shell \
	grep -rl "pthread_" --include '*-*.c' posixtestsuite/conformance/interfaces/* | \
	grep -Ev 'speculative|posixtestsuite/conformance/interfaces/pthread_mutex_timedlock' | \
	xargs grep -EL 'clock_settime|sleep|fork|sigaction|semaphore.h|pthread_sigmask|\
		PTHREAD_PROCESS_SHARED|pthread_getcpuclockid|alarm' | \
	sort)

POSIX_TEST_SUITES = $(filter-out $(POSIX_TEST_SUITES_BLACKLIST), $(POSIX_TEST_SUITES_ALL))

posixtestsuite-build: $(patsubst posixtestsuite/%.c, bin/posixtestsuite/%, $(POSIX_TEST_SUITES))
posixtestsuite-test: $(patsubst posixtestsuite/%.c, bin/posixtestsuite/%.test, $(POSIX_TEST_SUITES))

unthread-test: $(patsubst test-src/%.c, bin/%.test, $(wildcard test-src/*.c))
unthread-test-schedules: $(patsubst test-src/%.c, test-src/%.json, $(wildcard test-src/*.c))

posixtestsuite:
	wget -O - https://sourceforge.net/projects/posixtest/files/latest/download | tar -xzf -

test: posixtestsuite-test unthread-test

clean:
	rm -r bin

.PHONY: test test-schedules clean
.PRECIOUS: bin/%