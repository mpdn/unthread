#ifndef UNTHREAD_TEST
#define UNTHREAD_TEST

// Utility library for Unthread. This header can be used with or without the
// Unthread library itself.
//
// unthread_yield: yields only when using Unthread.
// unthread_test: returns true when using Unhtread and false otherwise.

#include <pthread.h>
#include <stdbool.h>

#ifdef UNTHREAD
void unthread_yield() { pthread_yield(); }

static inline bool unthread_test() { return true; }
#else
static inline void unthread_yield() {}

static inline bool unthread_test() { return false; }
#endif

#endif