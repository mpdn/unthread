#ifndef PTHREADTYPES_H
#define PTHREADTYPES_H

#include <bits/types/struct_sched_param.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct pthread_fiber *pthread_t;

// We would rather not expose these internals, but C does not leave us much
// choice unless we want to heap allocate each of these.

struct pthread_fiber;
struct pthread_list {
  size_t len;
  size_t cap;
  union {
    // Store a small list inline or a large list on the heap. Possibly an
    // unnecessary micro-optimization, but eh.
    struct pthread_fiber *small[4];
    struct pthread_fiber **big;
  } threads;
};

struct pthread_multiset_entry;

// Multiset of threads. Used for keeping track of readers in rwlocks.
struct pthread_multiset {
  size_t len;
  size_t cap;
  struct pthread_multiset_entry *entries;
};

typedef struct pthread_cleanup_t {
  void (*routine)(void *);
  void *arg;
  struct pthread_cleanup_t *prev;
} pthread_cleanup_t;

typedef struct {
  int initialized;
  int prioceiling;
  int protocol;
  int pshared;
  int type;
  int robust;
} pthread_mutexattr_t;

// pthread_attr_t is defined as a union somewhere in some glibc header, so we
// pretend its a union here as well.
union pthread_attr_t {
  struct {
    int initialized;
    int detach_state;
    size_t guard_size;
    int inherit_sched;
    int scope;
    struct sched_param sched_param;
    int sched_policy;
    void **stack_addr;
    size_t stack_size;
  } data;
};

// glibc workaround
#ifndef __have_pthread_attr_t
typedef union pthread_attr_t pthread_attr_t;
#define __have_pthread_attr_t 1
#endif

typedef struct {
  int initialized;
  int pshared;
  clockid_t clock_id;
} pthread_condattr_t;

typedef struct {
  int initialized;
  struct pthread_list waiting;
} pthread_cond_t;

typedef struct {
  int initialized;
  struct pthread_fiber *locked_by;
  struct pthread_list waiting;
  int type;
  unsigned int rec_count;
  int prioceiling;
  int robust;
} pthread_mutex_t;

typedef struct {
  int initialized;
  unsigned int id;
  void (*destructor)(void *);
} pthread_key_t;

typedef struct {
  int initialized;
  int pshared;
} pthread_rwlockattr_t;

typedef struct {
  int initialized;
  struct pthread_fiber *writer;
  struct pthread_multiset readers;
  struct pthread_list pending_readers;
  struct pthread_list pending_writers;
} pthread_rwlock_t;

typedef struct {
  int initialized;
  size_t count;
  struct pthread_list waiting;
  struct pthread_fiber *serial;
} pthread_barrier_t;

typedef struct {
  int initialized;
  int pshared;
} pthread_barrierattr_t;

typedef struct {
  int initialized;
  pthread_mutex_t mutex;
} pthread_spinlock_t;

typedef int pthread_once_t;

#endif