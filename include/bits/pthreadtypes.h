#ifndef _BITS_PTHREADTYPES_COMMON_H
# define _BITS_PTHREADTYPES_COMMON_H	1

#include <bits/thread-shared-types.h>
#include <bits/types/struct_sched_param.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct unthread_fiber;
struct unthread_list {
  unsigned int len;
  struct unthread_fiber *head;
};

#define UNTHREAD_EMPTY_LIST_INITIALIZER { 0, NULL }

struct unthread_multiset_entry;

// Multiset of threads. Used for keeping track of readers in rwlocks.
struct unthread_multiset {
  unsigned int len;
  unsigned int cap;
  struct pthread_multiset_entry *entries;
};

typedef int pthread_once_t;

typedef unsigned long int pthread_t;

typedef union
{
  char __size[__SIZEOF_PTHREAD_MUTEXATTR_T];
  int __align;
  struct {
    int initialized : 1;
    int prioceiling : 1;
    int protocol : 1;
    int pshared : 1;
    int type : 1;
    int robust : 1;
  } ut;
} pthread_mutexattr_t;
_Static_assert(sizeof(pthread_mutexattr_t) == __SIZEOF_PTHREAD_MUTEXATTR_T, "pthread_mutexattr_t too large");

typedef union
{
  char __size[__SIZEOF_PTHREAD_CONDATTR_T];
  int __align;
  struct {
    int initialized: 1;
    int pshared: 1;
    clockid_t clock_id : 28;
  } ut;
} pthread_condattr_t;
_Static_assert(sizeof(pthread_condattr_t) == __SIZEOF_PTHREAD_CONDATTR_T, "pthread_condattr_t too large");

typedef unsigned int pthread_key_t;

typedef int __ONCE_ALIGNMENT pthread_once_t;

union pthread_attr_t
{
  char __size[__SIZEOF_PTHREAD_ATTR_T];
  long int __align;
  struct {
    int initialized;
    int kind;
    int detach_state;
    size_t guard_size;
    int inherit_sched;
    int scope;
    struct sched_param sched_param;
    int sched_policy;
    void **stack_addr;
    size_t stack_size;
  } ut;
};

#ifndef __have_pthread_attr_t
typedef union pthread_attr_t pthread_attr_t;
# define __have_pthread_attr_t 1
#endif

_Static_assert(sizeof(pthread_attr_t) == __SIZEOF_PTHREAD_ATTR_T, "pthread_attr_t too large");

typedef union
{
  struct __pthread_mutex_s __data;
  char __size[__SIZEOF_PTHREAD_MUTEX_T];
  long int __align;
  struct {
    struct unthread_fiber *locked_by;
    struct unthread_list waiting;
    int kind;
    unsigned int rec_count;
    int prioceiling;
    int robust;
  } ut;
} pthread_mutex_t;
_Static_assert(sizeof(pthread_mutex_t) == __SIZEOF_PTHREAD_MUTEX_T, "pthread_mutex_t too large");

typedef union
{
  struct __pthread_cond_s __data;
  char __size[__SIZEOF_PTHREAD_COND_T];
  __extension__ long long int __align;
  struct {
    int initialized;
    struct unthread_list waiting;
  } ut;
} pthread_cond_t;
_Static_assert(sizeof(pthread_cond_t) == __SIZEOF_PTHREAD_COND_T, "pthread_cond_t too large");

typedef union
{
  struct __pthread_rwlock_arch_t __data;
  char __size[__SIZEOF_PTHREAD_RWLOCK_T];
  long int __align;
  struct {
    struct unthread_fiber *writer;
    struct unthread_multiset readers;
    struct unthread_list pending_readers;
    struct unthread_list pending_writers;
  } ut;
} pthread_rwlock_t;
_Static_assert(sizeof(pthread_rwlock_t) == __SIZEOF_PTHREAD_RWLOCK_T, "pthread_rwlock_t too large");

typedef union
{
  char __size[__SIZEOF_PTHREAD_RWLOCKATTR_T];
  long int __align;
  struct {
    int initialized;
    int pshared;
  } ut;
} pthread_rwlockattr_t;
_Static_assert(sizeof(pthread_rwlockattr_t) == __SIZEOF_PTHREAD_RWLOCKATTR_T, "pthread_rwlockattr_t too large");

typedef volatile int pthread_spinlock_t;

typedef union
{
  char __size[__SIZEOF_PTHREAD_BARRIER_T];
  long int __align;
  struct {
    unsigned int count;
    struct unthread_list waiting;
    struct unthread_fiber *serial;
  } ut;
} pthread_barrier_t;
_Static_assert(sizeof(pthread_barrier_t) == __SIZEOF_PTHREAD_BARRIER_T, "pthread_barrier_t too large");

typedef union
{
  char __size[__SIZEOF_PTHREAD_BARRIERATTR_T];
  int __align;
  struct {
    int pshared;
  } ut;
} pthread_barrierattr_t;
_Static_assert(sizeof(pthread_barrierattr_t) == __SIZEOF_PTHREAD_BARRIERATTR_T, "pthread_barrierattr_t too large");

#endif