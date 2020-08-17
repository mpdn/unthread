#ifndef PTHREAD_H
#define PTHREAD_H

#include <bits/pthreadtypes.h>
#include <limits.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <time.h>

#define UNTHREAD

#define PTHREAD_EMPTY_LIST_INITIALIZER                     \
  {                                                        \
    .len = 0,                                              \
    .cap = sizeof((struct pthread_list){}.threads.small) / \
           sizeof(*(struct pthread_list){}.threads.small), \
  }

static const struct pthread_list pthread_empty_list =
    PTHREAD_EMPTY_LIST_INITIALIZER;

#define PTHREAD_CANCELED ((void *)(-1))

#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#define PTHREAD_CANCEL_ENABLE 2
#define PTHREAD_CANCEL_DEFERRED 3
#define PTHREAD_CANCEL_DISABLE 4
#define PTHREAD_CREATE_DETACHED 5
#define PTHREAD_CREATE_JOINABLE 6
#define PTHREAD_EXPLICIT_SCHED 7
#define PTHREAD_INHERIT_SCHED 8
#define PTHREAD_MUTEX_DEFAULT 9
#define PTHREAD_MUTEX_ERRORCHECK 10
#define PTHREAD_MUTEX_NORMAL 11
#define PTHREAD_MUTEX_RECURSIVE 12
#define PTHREAD_MUTEX_ROBUST 13
#define PTHREAD_MUTEX_STALLED 14
#define PTHREAD_PRIO_INHERIT 15
#define PTHREAD_PRIO_NONE 16
#define PTHREAD_PRIO_PROTECT 17
#define PTHREAD_PROCESS_SHARED 18
#define PTHREAD_PROCESS_PRIVATE 19
#define PTHREAD_SCOPE_PROCESS 20
#define PTHREAD_SCOPE_SYSTEM 21
#define PTHREAD_BARRIER_SERIAL_THREAD 22

void pthread_cleanup_push_inner(pthread_cleanup_t *cleanup);
void pthread_cleanup_pop_inner(int execute);

#define pthread_cleanup_push(routine, arg)                             \
  {                                                                    \
    pthread_cleanup_t _pthread_cleanup##__LINE__ = {(routine), (arg)}; \
    pthread_cleanup_push_inner(&_pthread_cleanup##__LINE__)

#define pthread_cleanup_pop(execute)  \
  pthread_cleanup_pop_inner(execute); \
  }

#define PTHREAD_MUTEX_INITIALIZER                                           \
  {                                                                         \
    .locked_by = NULL, .initialized = 1,                                    \
    .waiting = PTHREAD_EMPTY_LIST_INITIALIZER, .type = PTHREAD_MUTEX_NORMAL \
  }

#define PTHREAD_COND_INITIALIZER \
  { .waiting = PTHREAD_EMPTY_LIST_INITIALIZER, .initialized = 1 }

#define PTHREAD_RWLOCK_INITIALIZER                     \
  {                                                    \
    .initialized = 1, .writer = NULL,                  \
    .pending_readers = PTHREAD_EMPTY_LIST_INITIALIZER, \
    .pending_writers = PTHREAD_EMPTY_LIST_INITIALIZER  \
  }
#define PTHREAD_ONCE_INIT 1

int pthread_getschedparam(pthread_t thread, int *policy,
                          struct sched_param *param);
int pthread_setschedparam(pthread_t thread, int policy,
                          const struct sched_param *param);

int pthread_attr_destroy(pthread_attr_t *);
int pthread_attr_getdetachstate(const pthread_attr_t *, int *);
int pthread_attr_getguardsize(const pthread_attr_t *, size_t *);
int pthread_attr_getinheritsched(const pthread_attr_t *, int *);
int pthread_attr_getschedparam(const pthread_attr_t *, struct sched_param *);
int pthread_attr_getschedpolicy(const pthread_attr_t *, int *);
int pthread_attr_getscope(const pthread_attr_t *, int *);
int pthread_attr_getstackaddr(const pthread_attr_t *, void **);
int pthread_attr_getstacksize(const pthread_attr_t *, size_t *);
int pthread_attr_getstack(pthread_attr_t *attr, void **stackaddr,
                          size_t *stacksize);
int pthread_attr_init(pthread_attr_t *);
int pthread_attr_setdetachstate(pthread_attr_t *, int);
int pthread_attr_setguardsize(pthread_attr_t *, size_t);
int pthread_attr_setinheritsched(pthread_attr_t *, int);
int pthread_attr_setschedparam(pthread_attr_t *, const struct sched_param *);
int pthread_attr_setschedpolicy(pthread_attr_t *, int);
int pthread_attr_setscope(pthread_attr_t *, int);
int pthread_attr_setstackaddr(pthread_attr_t *, void *);
int pthread_attr_setstacksize(pthread_attr_t *, size_t);
int pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr,
                          size_t stacksize);

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);

int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
int pthread_cancel(pthread_t);
int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *),
                   void *);
int pthread_join(pthread_t thread, void **retval);
void pthread_exit(void *retval);
int pthread_yield();
pthread_t pthread_self();
int pthread_detach(pthread_t thread);
int pthread_equal(pthread_t, pthread_t);
void pthread_testcancel(void);

int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex,
                            const struct timespec *abs_timeout);
int pthread_mutex_getprioceiling(const pthread_mutex_t *mutex,
                                 int *prioceiling);
int pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int prioceiling,
                                 int *old_ceiling);
int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *, int *);
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *, int *);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *, int *);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *, int *);
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *, int *);
int pthread_mutexattr_init(pthread_mutexattr_t *);
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *, int);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *, int);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *, int);
int pthread_mutexattr_setrobust(pthread_mutexattr_t *, int);
int pthread_mutexattr_settype(pthread_mutexattr_t *, int);
int pthread_mutexattr_destroy(pthread_mutexattr_t *);

int pthread_cond_broadcast(pthread_cond_t *);
int pthread_cond_destroy(pthread_cond_t *);
int pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int pthread_cond_signal(pthread_cond_t *);
int pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *,
                           const struct timespec *);
int pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);

int pthread_condattr_destroy(pthread_condattr_t *);
int pthread_condattr_getpshared(const pthread_condattr_t *, int *);
int pthread_condattr_getclock(pthread_condattr_t *restrict attr,
                              clockid_t *restrict clock_id);
int pthread_condattr_init(pthread_condattr_t *);
int pthread_condattr_setpshared(pthread_condattr_t *, int);
int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id);

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
void *pthread_getspecific(pthread_key_t key);

int pthread_rwlock_destroy(pthread_rwlock_t *);
int pthread_rwlock_init(pthread_rwlock_t *, const pthread_rwlockattr_t *);
int pthread_rwlock_rdlock(pthread_rwlock_t *);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *, const struct timespec *);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *, const struct timespec *);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *);
int pthread_rwlock_trywrlock(pthread_rwlock_t *);
int pthread_rwlock_unlock(pthread_rwlock_t *);
int pthread_rwlock_wrlock(pthread_rwlock_t *);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *restrict,
                                  int *restrict);
int pthread_rwlockattr_init(pthread_rwlockattr_t *);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *, int);

int pthread_barrierattr_init(pthread_barrierattr_t *attr);
int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr,
                                   int *pshared);
int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_init(pthread_barrier_t *restrict barrier,
                         const pthread_barrierattr_t *attr, unsigned count);
int pthread_barrier_wait(pthread_barrier_t *barrier);

int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock(pthread_spinlock_t *lock);

int pthread_getcpuclockid(pthread_t thread, clockid_t *clockid);
int pthread_setschedprio(pthread_t thread, int prio);
int pthread_kill(pthread_t thread, int sig);

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));

int pthread_getconcurrency(void);
int pthread_setconcurrency(int new_level);

#endif