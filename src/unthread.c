#define _GNU_SOURCE
#undef _FORTIFY_SOURCE

#include <../include/pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <ucontext.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

#define NAME "unthread"
#define NOISE_BUF_SIZE 1024

#ifndef UNTHREAD_MAX_RECURSIVE_LOCKS
#define UNTHREAD_MAX_RECURSIVE_LOCKS 1024
#endif

#define CHECK(reason, cond, message, ...)                            \
    do {                                                             \
        if (!(cond)) {                                               \
            fprintf(stderr, NAME ": " message "\n",  ##__VA_ARGS__); \
            exit_reasoned(reason);                                   \
        }                                                            \
    } while (false)

#define CHECK_RET(ret, cond, message, ...)                           \
    do {                                                             \
        if (!(cond)) {                                               \
            LOG(message,  ##__VA_ARGS__);                            \
            return ret;                                              \
        }                                                            \
    } while (false)

#define LOG(message, ...)                                            \
    do {                                                             \
        if (verbose) {                                               \
            fprintf(stderr, NAME ": " message "\n", ##__VA_ARGS__);  \
        }                                                            \
    } while (false)

#define ASSERT_UNREACHABLE() (assert(!("Unthread: This should be unreachable")))

static bool verbose;

enum thread_state {
    TERMINATED,
    STARTED,
    STOPPED,
    RUNNING,

    BLOCK_YIELD,
    BLOCK_LOCK,
    BLOCK_JOIN,
    BLOCK_MUTEX_LOCK,
    BLOCK_MUTEX_TIMEDLOCK,
    BLOCK_COND_WAIT,
    BLOCK_COND_TIMEDWAIT,
    BLOCK_RWLOCK_RDLOCK,
    BLOCK_RWLOCK_WRLOCK,
    BLOCK_RWLOCK_TIMEDRDLOCK,
    BLOCK_RWLOCK_TIMEDWRLOCK,
    BLOCK_BARRIER_WAIT,
};

struct exit_reason {
    int retcode_offset;
};

static const struct exit_reason EXIT_ENTROPY = { 0 };
static const struct exit_reason EXIT_DEADLOCK = { 1 };
static const struct exit_reason EXIT_ILLEGAL = { 2 };
static const struct exit_reason EXIT_ALLOC = { 3 };
static const struct exit_reason EXIT_MISC = { 4 };
static const struct exit_reason EXIT_IO = { 5 };
static const struct exit_reason EXIT_UNSUPPORTED = { 6 };

#define RETCODE_OFFSET_ENV "UNTHREAD_RET_OFFSET"
#define PRNG_SEED_ENV "UNTHREAD_SEED"
#define VERBOSE_ENV "UNTHREAD_VERBOSE"
#define NOISE_FILE_ENV "UNTHREAD_NOISE"

static void exit_reasoned(const struct exit_reason reason) {
    int retcode_offset = 40;
    const char *retcode_str = getenv(RETCODE_OFFSET_ENV);

    if (retcode_str != NULL) {
        char *endptr = NULL;
        long retcodel = strtol(retcode_str, &endptr, 10);
    
        if (endptr != retcode_str &&
            errno == 0 &&
            *endptr == 0 &&
            retcodel > INT_MIN &&
            retcodel < INT_MAX
        ) {
            retcode_offset = (int)retcodel;
        } else {
            fprintf(stderr, NAME ": Failed parsing retcode offset in '" RETCODE_OFFSET_ENV "'\n");
        }
    }

    exit(retcode_offset + reason.retcode_offset);
}

static const size_t HASH_LOAD_NOM = 4;
static const size_t HASH_LOAD_DENOM = 5;

struct tls_entry {
    size_t id;
    void *value;
    void (*destructor)(void*);
};

struct tls {
    struct tls_entry *entries;
    size_t cap, len;
};

struct pthread_fiber {
    bool detached;
    bool owns_stack;
    enum thread_state state;

    // The indexes of 
    size_t list_index[2];

    pthread_attr_t attr;

    unsigned int id;

    union {
        // When blocked on pthread_join, contains the thread being joined
        pthread_t joining;

        // When blocked on pthread_cond_wait and pthread_cond_timedwait, this will be the mutex to
        // acquire when the condition variable is signalled.
        pthread_mutex_t *cond_mutex;

        // When blocked on pthread_barrier_wait, this will be true if the thread was chosen as the
        // serial thread of the barrier.
        bool barrier_serial;

        // When a thread is stopped, this will be the return value of the thread.
        void *retval;

        // When blocked on pthread_rwlock or pthread_rwlock_timedrdlock, this is whether the current
        // thread has been granted reader access.
        bool rwlock_reader;
    } state_data;

    // The thread that this thread is being joined by, or NULL if no thread is currently joining
    // this thread.
    pthread_t joined_by;

    // Thread local storage map for this thread
    struct tls tls;

    // Jump buffer to jump to in order to switch to this thread.
    jmp_buf jmp;

    int cancel_state;
    int cancel_type;

    // Whether a cancellation signal has been sent. Since the signal is asynchronous, we may act on
    // them much sooner than it is sent.
    bool canceled;

    pthread_cleanup_t *cleanup;

    int sched_policy;
    struct sched_param sched_param;

    __attribute__((aligned (16)))
    char stack[];
};

static const pthread_attr_t default_attr = {{
    .initialized = true,
    .detach_state = PTHREAD_CREATE_JOINABLE,
    .guard_size = 0,
    .inherit_sched = PTHREAD_INHERIT_SCHED,
    .scope = PTHREAD_SCOPE_PROCESS,
    .sched_param = (struct sched_param) { },
    .sched_policy = SCHED_OTHER,
    .stack_addr = NULL,
    .stack_size = 1 << 20,
}};

static struct pthread_fiber main_thread = {
    .id = 1,
    .state = RUNNING,
    .attr = default_attr,
    .cancel_state = PTHREAD_CANCEL_ENABLE,
    .cancel_type = PTHREAD_CANCEL_DEFERRED,
    .sched_policy = SCHED_OTHER,
};

static size_t next_key_id = 1;
static unsigned int next_id = 2;
static pthread_t current = &main_thread;
static struct pthread_list threads_ready = pthread_empty_list;
static size_t threads_count = 1;
static FILE *noise_file;
static uint8_t noise_buf[NOISE_BUF_SIZE];
static size_t noise_offset = 0;
static size_t noise_len = 0; 
static uint32_t noise_min = 0;
static uint32_t noise_max = UINT32_MAX;

static bool noise_prng;
static uint32_t noise_prng_state[4];

void __attribute__((constructor)) pthread_constructor() {
    const char *verbose_str = getenv(VERBOSE_ENV);
    verbose = (verbose_str != NULL && strcmp(verbose_str, "true") == 0);

    const char *prng_str = getenv(PRNG_SEED_ENV);
    const char *file_str = getenv(NOISE_FILE_ENV);

    if (prng_str != NULL) {
        noise_prng = true;

        const size_t HEX_ELEM_LEN = sizeof(*noise_prng_state) * 2;
        const size_t HEX_ARRAY_LEN = sizeof(noise_prng_state) * 2;

        CHECK(EXIT_MISC, strlen(prng_str) == HEX_ARRAY_LEN,
            "Seed has incorrect length (%zu) - must be %zu characters",
            strlen(prng_str), HEX_ARRAY_LEN);

        for (size_t i = 0; i < HEX_ARRAY_LEN; i++) {
            char c = prng_str[i];

            int unhexed =
                c >= '0' && c <= '9' ? c - '0' :
                c >= 'a' && c <= 'f' ? 10 + (c - 'a') :
                c >= 'A' && c <= 'F' ? 10 + (c - 'A') :
                -1;

            CHECK(EXIT_MISC, unhexed != -1,
                "Seed has invalid character (%c) - must be a hex character", c);
            
            noise_prng_state[i / HEX_ELEM_LEN] <<= 4;
            noise_prng_state[i / HEX_ELEM_LEN] |= unhexed;
        }
    } else if (file_str != NULL) {
        noise_file = fopen(file_str, "r");
        CHECK(EXIT_IO, noise_file != NULL, "Failed reading noise file: %s", strerror(errno));
    } else {
        noise_file = stdin;
    }
}

static inline uint32_t rotl(const uint32_t x, int k) {
	return (x << k) | (x >> (32 - k));
}

// xoshiro128** 1.1
// TODO: attribute better
uint32_t rand_u32_prng(uint32_t len) {
	const uint32_t result = rotl(noise_prng_state[1] * 5, 7) * 9;
	const uint32_t t = noise_prng_state[1] << 9;
	noise_prng_state[2] ^= noise_prng_state[0];
	noise_prng_state[3] ^= noise_prng_state[1];
	noise_prng_state[1] ^= noise_prng_state[2];
	noise_prng_state[0] ^= noise_prng_state[3];
	noise_prng_state[2] ^= t;
	noise_prng_state[3] = rotl(noise_prng_state[3], 11);
	return ((uint64_t)result * len) >> 32;
}

static uint32_t rand_u32_io(uint32_t len) {
    // Pick a random number by interpreting the noise input as an arithmetic coded stream.
    //
    // This has two benefits:
    //
    // 1. The picks are uniformly random (or at least very close).
    // 2. The picks use the noise input very efficiently; one bit change is guarenteed to change
    //    the picked outcome. This can potentially make fuzzing explore a larger space quicker.
    //
    // It's not totally clear if the above benefits outweighs its generally slow performance.

    assert(len > 0);

    if (len == 1) {
        return 0;
    }

    uint32_t segment_min, segment_max;

    while (true) {
        segment_min = ((uint64_t)noise_min * len) >> 32;
        segment_max = ((uint64_t)noise_max * len) >> 32;
        
        if (segment_min == segment_max) {
            break;
        }

        if (noise_offset >= noise_len) {
            noise_len = fread(noise_buf, sizeof(*noise_buf),
                sizeof(noise_buf) / sizeof(*noise_buf), stdin);
            noise_offset = 0;

            CHECK(EXIT_ENTROPY, noise_len != 0 || !feof(stdin), "Entropy exhausted");
            CHECK(EXIT_IO, noise_len != 0, "IO Error: %s", strerror(ferror(stdin)));
        }

        uint64_t noise_size = (uint64_t)(noise_max - noise_min) + 1;
        uint8_t noise_segment = noise_buf[noise_offset++];

        noise_min += (noise_size * noise_segment) >> 8;
        noise_max -= ((noise_size * (UINT8_MAX - noise_segment)) >> 8) - 1;
    }

    uint32_t pick = segment_min;
    assert(pick < len);

    uint32_t segment_range_min = ((uint64_t)(pick + 0) << 32) / len;
    uint32_t segment_range_max = ((uint64_t)(pick + 1) << 32) / len - 1;
    uint32_t segment_range_size = segment_range_max - segment_range_min + 1;

    assert(noise_min >= segment_range_min);
    assert(noise_max <= segment_range_max);

    // Renormalize to the picked segment.
    noise_min = ((uint64_t)(noise_min - segment_range_min) << 32) / segment_range_size;
    noise_max = UINT32_MAX - ((uint64_t)(segment_range_max - noise_max) << 32) / segment_range_size;

    return pick;
}

static uint32_t rand_u32(uint32_t len) {
    return noise_prng
        ? rand_u32_prng(len)
        : rand_u32_io(len);
}

static void ensure_cap(struct pthread_list *list, size_t additional) {
    if (list->len + additional > list->cap) {
        size_t old_cap = list->cap;
        size_t new_cap = old_cap;

        CHECK(EXIT_ILLEGAL, old_cap != 0,
            "Capacity should not be 0 (was pthread object zero-initialized?)");

        do {
            new_cap *= 2;
        } while (list->len + additional > new_cap);

        if (old_cap > pthread_empty_list.cap) {
            list->threads.big = realloc(list->threads.big, new_cap * sizeof(struct pthread_fiber*));
            CHECK(EXIT_ALLOC, list->threads.big != NULL, "Allocating threads failed");
        } else {
            pthread_t *big = malloc(new_cap * sizeof(struct pthread_fiber*));
            CHECK(EXIT_ALLOC, big != NULL, "Allocating threads failed");
            memcpy(big, list->threads.small, list->len * sizeof(struct pthread_fiber*));
            list->threads.big = big;
        }

        list->cap = new_cap;
    }
}

static struct pthread_fiber** threads_ptr(struct pthread_list* list) {
    return list->cap > pthread_empty_list.cap
        ? list->threads.big
        : list->threads.small;
}

static void push(struct pthread_list* list, pthread_t thread) {
    ensure_cap(list, 1);
    size_t index = list->len++;
    threads_ptr(list)[index] = thread;
    thread->list_index[list != &threads_ready] = index;
}

static void append(struct pthread_list *target, struct pthread_list* source) {
    ensure_cap(target, source->len);

    pthread_t *target_ptr = threads_ptr(target) + target->len;

    memcpy(
        target_ptr,
        threads_ptr(source),
        sizeof(*threads_ptr(source)) * source->len);

    for (size_t i = 0; i < source->len; i++) {
        target_ptr[i]->list_index[target != &threads_ready] += target->len;
    }

    target->len += source->len;
    source->len = 0;
}

static struct pthread_fiber* pop_random(struct pthread_list* list) {
    assert(list->len > 0);

    size_t pick = 0;

    if (list->len >= 1) {
        pick = rand_u32(list->len);
    }

    pthread_t *threads = threads_ptr(list);
    pthread_t popped = threads[pick];
    threads[pick] = threads[--list->len];
    threads[pick]->list_index[list != &threads_ready] = pick;
    return popped;
}

static void pop_specific(struct pthread_list* list, pthread_t thread) {
    pthread_t *threads = threads_ptr(list);
    threads[thread->list_index[list != &threads_ready]] = threads[--list->len];
}

static void multisetset_insert_base(
    struct pthread_multiset *set,
    struct pthread_multiset_entry entry
) {
    size_t mask = set->cap - 1;
    size_t index = (size_t)(entry.thread) & mask;
    size_t dist = 0;

    for (;;) {
        struct pthread_multiset_entry *table_entry = &set->entries[index];

        if (table_entry->thread == NULL) {
            *table_entry = entry;
            set->len++;
            break;
        } else if (table_entry->thread == entry.thread) {
            if (table_entry->count == 0) {
                set->len++;
            }

            table_entry->count += entry.count;
            break;
        }

        size_t probe_distance = (index - (size_t)table_entry->thread) & mask;

        if (dist > probe_distance) {
            if (table_entry->count == 0) {
                *table_entry = entry;
                set->len++;
            }

            struct pthread_multiset_entry tmp = *table_entry;
            *table_entry = entry;
            entry = tmp;
        }

        dist++;
        index++;
        index &= mask;
    }
}

static void multiset_grow(struct pthread_multiset *set) {
    size_t new_cap = set->cap * 2;

    if (new_cap < 16) {
        new_cap = 16;
    }

    struct pthread_multiset new_set = (struct pthread_multiset) {
        .entries = malloc(new_cap * sizeof(struct pthread_multiset_entry)),
        .cap = new_cap,
        .len = 0,
    };

    CHECK(EXIT_ALLOC, new_set.entries != NULL, "Allocation failed");

    for (size_t i = 0; i < set->cap; i++) {
        if (set->entries[i].thread != NULL) {
            multisetset_insert_base(&new_set, set->entries[i]);
        }
    }

    free(set->entries);
    *set = new_set;
}

static void multiset_insert(struct pthread_multiset *set, pthread_t thread) {
    if (set->cap * HASH_LOAD_NOM <= set->len * HASH_LOAD_DENOM) {
        multiset_grow(set);
    }

    multisetset_insert_base(set, (struct pthread_multiset_entry) {
        .thread = thread,
        .count = 1,
    });
}

static bool multiset_remove(struct pthread_multiset *set, pthread_t thread) {
    size_t mask = set->cap - 1;
    size_t index = (size_t)thread & mask;
    size_t dist = 0;

    for (;;) {
        struct pthread_multiset_entry *table_entry = &set->entries[index];

        if (table_entry->thread == NULL) {
            return false;
        } else if (table_entry->thread == thread) {
            if (table_entry->count == 0) {
                return false;
            }

            table_entry->count--;

            if (table_entry->count == 0) {
                set->len--;
            }

            return true;
        }

        size_t probe_distance = (index - (size_t)table_entry->thread) & mask;
        if (dist > probe_distance) {
            return false;
        }

        dist++;
        index++;
        index &= mask;
    }
}

// Yield without marking the current thread as ready
static bool yield(enum thread_state blocked_state) {
    CHECK(EXIT_DEADLOCK, threads_ready.len != 0, "Deadlock");

    pthread_t yield_to = pop_random(&threads_ready);
    bool yielding = yield_to != current;

    if (yielding) {
        current->state = blocked_state;
        LOG("%u yielding to %u", current->id, yield_to->id);

        pthread_t this_thread = current;

        if (_setjmp(this_thread->jmp) == 0) {
            _longjmp(yield_to->jmp, 1);
        }

        current = this_thread;
        current->state = RUNNING;
    }

    return yielding;
}

int pthread_yield() {
    if (current->canceled && current->cancel_state == PTHREAD_CANCEL_ENABLE &&
        current->cancel_type == PTHREAD_CANCEL_ASYNCHRONOUS && rand_u32(2))
    {
        pthread_exit(PTHREAD_CANCELED);
    }

    push(&threads_ready, current);
    yield(BLOCK_YIELD);
    return 0;
}

pthread_t pthread_self() {
    return current;
}

static void terminate(pthread_t thread) {
    assert(thread->state != TERMINATED);

    if (thread->state != STOPPED) {
        threads_count--;
    }

    thread->state = TERMINATED;

    if (thread->owns_stack) {
        free(thread);
    }
}

int pthread_equal(pthread_t a, pthread_t b) {
    return a == b ? 1 : 0;
}

int pthread_join(pthread_t join, void **retval) {
    pthread_yield();
    
    LOG("%u join with %u", current->id, join->id);
    
    CHECK(EXIT_ILLEGAL, join->state != TERMINATED && !join->detached,
        "%u tried joining %u, but %u is not in a joinable state",
        current->id, join->id, join->id);

    if (join->state != STOPPED) {
        CHECK(EXIT_ILLEGAL, join->joined_by == NULL,
            "%u tried joining %u, but %u already has a thread joining it",
            current->id, join->id, join->id);

        join->joined_by = current;

        if (current->canceled && current->cancel_state == PTHREAD_CANCEL_ENABLE) {
            push(&threads_ready, current);
        }
        
        current->state_data.joining = join;
        yield(BLOCK_JOIN);

        if (join->state != STOPPED) {
            // We were awakened without the thread we are joining having stopped - we must have been
            // canceled.
            assert(current->canceled);
            join->joined_by = NULL;
            pthread_exit(PTHREAD_CANCELED);
        } else if (current->canceled) {
            pop_specific(&threads_ready, current);
        }
    }

    LOG("%u finished join with %u", current->id, join->id);

    assert(join->state == STOPPED);

    if (retval != NULL) {
        *retval = join->state_data.retval;
    }

    terminate(join);

    pthread_yield();

    return 0;
}

struct thread_start_ctx {
    pthread_t thread;
    ucontext_t* prv;
    void* (*start_func)(void*);
    void* start_arg;
};

static void start_thread_fn(void* p) {
    struct thread_start_ctx ctx = *(struct thread_start_ctx*)p;

    if (_setjmp(ctx.thread->jmp) == 0) {
        ucontext_t tmp;
        swapcontext(&tmp, ctx.prv);
    }

    current = ctx.thread;
    pthread_exit(ctx.start_func(ctx.start_arg));
}

int pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attr,
    void *(*func)(void *),
    void *arg
) {
    pthread_yield();

    if (attr == NULL) {
        attr = &default_attr;
    }

    bool owns_stack = attr->data.stack_addr != NULL;

    pthread_t child = owns_stack
        ? attr->data.stack_addr
        : malloc(attr->data.stack_size);

    unsigned int id;

    do {
        id = next_id++;
    } while (id == 0);
    
    *child = (struct pthread_fiber){
        .id = id,
        .state = STARTED,
        .owns_stack = owns_stack,
        .detached = attr->data.detach_state == PTHREAD_CREATE_DETACHED,
        .sched_policy = attr->data.inherit_sched == PTHREAD_EXPLICIT_SCHED
            ? attr->data.sched_policy
            : current->sched_policy,
        .sched_param = attr->data.inherit_sched == PTHREAD_EXPLICIT_SCHED
            ? attr->data.sched_param
            : current->sched_param,
        .attr = *attr,
        .cancel_state = PTHREAD_CANCEL_ENABLE,
        .cancel_type = PTHREAD_CANCEL_DEFERRED,
    };

    *thread = child;

    LOG("%u starts %u", current->id, child->id);
    
    ucontext_t ctx, tmp;
    CHECK(EXIT_MISC, getcontext(&ctx) == 0,
        "Failed to get thread context: %s", strerror(errno));

    ctx.uc_stack.ss_sp = &child->stack;
    ctx.uc_stack.ss_size = attr->data.stack_size - sizeof(struct pthread_fiber);
    ctx.uc_link = 0;

    struct thread_start_ctx start_ctx = {
        .start_func = func,
        .start_arg = arg,
        .thread = child,
        .prv = &tmp,
    };

    makecontext(&ctx, (void(*)())start_thread_fn, 1, &start_ctx);
    CHECK(EXIT_MISC, swapcontext(&tmp, &ctx) == 0,
        "Failed to swap thread context: %s", strerror(errno));

    threads_count++;

    push(&threads_ready, child);

    pthread_yield();
    return 0;
}

int pthread_setcancelstate(int state, int *oldstate) {
    CHECK(EXIT_ILLEGAL, state == PTHREAD_CANCEL_ENABLE ||
        state == PTHREAD_CANCEL_DISABLE,
        "cancel state must be PTHREAD_CANCEL_ENABLE or PTHREAD_CANCEL_DISABLE");

    *oldstate = current->cancel_state;
    current->cancel_state = state;
    return 0;
}

int pthread_setcanceltype(int type, int *oldtype) {
    CHECK(EXIT_ILLEGAL, type == PTHREAD_CANCEL_DEFERRED ||
        type == PTHREAD_CANCEL_ASYNCHRONOUS,
        "cancel type must be PTHREAD_CANCEL_DEFERRED or PTHREAD_CANCEL_ASYNCHRONOUS");

    *oldtype = current->cancel_type;
    current->cancel_type = type;
    return 0;
}

int pthread_cancel(pthread_t thread) {
    if (!thread->canceled && thread->cancel_state == PTHREAD_CANCEL_ENABLE && (
        thread->state == BLOCK_COND_WAIT || thread->state == BLOCK_JOIN))
    {
        // The thread is blocked inside a function that is a cancellation point. The thread is now
        // considered "ready" because it can be awoken by the cancellation signal. 
        push(&threads_ready, thread);
    }

    thread->canceled = true;

    return 0;
}

int pthread_detach(pthread_t thread) {
    CHECK(EXIT_ILLEGAL, thread->state != TERMINATED,
        "Can only detach from non-terminated thread");

    CHECK(EXIT_ILLEGAL, !thread->detached,
        "Cannot detach already detached thread");

    if (thread->state == STOPPED) {
        terminate(thread);
    } else {
        thread->detached = true;
    }

    return 0;
}

void pthread_exit(void *retval) {
    LOG("%u exiting", current->id);

    pthread_yield();

    // Call cleanup functions
    for (
        pthread_cleanup_t *cleanup = current->cleanup;
        cleanup != NULL;
        cleanup = cleanup->prev
    ) {
        cleanup->routine(cleanup->arg);
    }

    bool tls_destructors_called;
    do {
        tls_destructors_called = false;
        for (size_t j = 0; j < current->tls.cap; j++) {
            struct tls_entry entry = current->tls.entries[j];

            if (entry.id != 0 && entry.destructor != NULL && entry.value != NULL) {
                entry.destructor(entry.value);
                tls_destructors_called = true;
            }

            current->tls.entries[j] = (struct tls_entry) {
                .id = 0,
                .value = NULL,
                .destructor = NULL,
            };
        }
    } while (tls_destructors_called);
    free(current->tls.entries);

    current->state_data.retval = retval;

    if (current->detached) {
        terminate(current);
    } else {
        current->state = STOPPED;
        threads_count--;

        // Mark any waiting threads as ready
        if (current->joined_by != NULL) {
            LOG("%u waking joining %u", current->id, current->joined_by->id);

            if (!current->joined_by->canceled ||
                current->joined_by->cancel_state == PTHREAD_CANCEL_DISABLE)
            {
                // If the joining thread is canceled, then the thread will already be in
                // threads_ready, so only push it there if it is not canceled.
                push(&threads_ready, current->joined_by);
            }
        }
    }

    if (threads_count == 0) {
        LOG("All threads exited");
        exit(0);
    }

    yield(STOPPED);
    ASSERT_UNREACHABLE();
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex is not initialized");

    CHECK(EXIT_ILLEGAL, mutex->locked_by == NULL,
        "%u tried destroying mutex at %p locked by %u",
        current->id, mutex, mutex->locked_by->id);

    if (mutex->waiting.cap > pthread_empty_list.cap) {
        free(mutex->waiting.threads.big);
    }

    pthread_mutex_init(mutex, NULL);

    pthread_yield();
    return 0;
}

static const pthread_mutexattr_t pthread_mutexattr_default = {
    .prioceiling = 0,
    .protocol = PTHREAD_PRIO_INHERIT,
    .pshared = PTHREAD_PROCESS_PRIVATE,
    .type = PTHREAD_MUTEX_DEFAULT,
    .initialized = true,
    .robust = PTHREAD_MUTEX_STALLED,
};

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    if (attr == NULL) {
        attr = &pthread_mutexattr_default;
    }

    CHECK(EXIT_UNSUPPORTED, attr->pshared == PTHREAD_PROCESS_PRIVATE,
        "System-shared mutexes are not supported");

    CHECK(EXIT_UNSUPPORTED, attr->type == PTHREAD_MUTEX_NORMAL ||
        attr->type == PTHREAD_MUTEX_DEFAULT || attr->type == PTHREAD_MUTEX_ERRORCHECK ||
        attr->type == PTHREAD_MUTEX_RECURSIVE, "Unsupported mutex type");

    CHECK(EXIT_UNSUPPORTED, attr->robust == PTHREAD_MUTEX_STALLED,
        "Failed creating mutex: robust mutexes not supported");

    *mutex = (pthread_mutex_t) {
        .locked_by = NULL,
        .waiting = pthread_empty_list,
        .initialized = true,
        .type = attr->type == PTHREAD_MUTEX_DEFAULT
            ? PTHREAD_MUTEX_NORMAL
            : attr->type,
        .rec_count = 0,
        .robust = attr->robust,
    };
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    
    if (mutex->locked_by == NULL) {
        mutex->locked_by = current;
        LOG("%u locked mutex at %p", current->id, mutex);
    } else if (mutex->type == PTHREAD_MUTEX_ERRORCHECK && current->id == mutex->locked_by->id) {
        LOG("%u tried relocking error-checked mutex %p, but failed due to lock already held",
            current->id, mutex);
        return EDEADLK;
    } else if (mutex->type == PTHREAD_MUTEX_RECURSIVE && current->id == mutex->locked_by->id) {
        CHECK(EXIT_ILLEGAL, mutex->rec_count <= UNTHREAD_MAX_RECURSIVE_LOCKS,
            "%u hit recusive lock limit on mutex at %p (%u)", current->id, mutex, mutex->rec_count);
        LOG("%u locked mutex at %p recursively (%u)", current->id, mutex, mutex->rec_count);
    } else if (false) {
        
    } else {
        LOG("%u blocked waiting for mutex at %p held by %u",
            current->id, mutex, mutex->locked_by->id);

        push(&mutex->waiting, current);
        yield(BLOCK_MUTEX_LOCK);
        assert(mutex->locked_by == current);
    }

    mutex->rec_count++;
    pthread_yield();
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    pthread_yield();

    if (mutex->locked_by == NULL) {
        LOG("%u locked mutex at %p", current->id, mutex);
        mutex->locked_by = current;
    } else if (mutex->type == PTHREAD_MUTEX_RECURSIVE && current == mutex->locked_by) {
        CHECK(EXIT_ILLEGAL, mutex->rec_count <= UNTHREAD_MAX_RECURSIVE_LOCKS,
            "%u hit recusive lock limit on mutex at %p (%u)", current->id, mutex, mutex->rec_count);
        LOG("%u locked mutex at %p recursively (%u)", current->id, mutex, mutex->rec_count);
    } else {
        return EBUSY;
    }

    mutex->rec_count++;
    pthread_yield();
    return 0;
}

int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abs_timeout) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    
    if (mutex->type == PTHREAD_MUTEX_RECURSIVE && current == mutex->locked_by) {
        CHECK(EXIT_ILLEGAL, mutex->rec_count <= UNTHREAD_MAX_RECURSIVE_LOCKS,
            "%u hit recusive lock limit on mutex at %p (%u)", current->id, mutex, mutex->rec_count);
        LOG("%u locked mutex at %p recursively (%u)", current->id, mutex, mutex->rec_count);
    } else {
        LOG("%u timedlock waiting for mutex at %p held by %u",
            current->id, mutex, mutex->locked_by->id);

        push(&mutex->waiting, current);
        push(&threads_ready, current);

        yield(BLOCK_MUTEX_TIMEDLOCK);

        if (mutex->locked_by != current) {
            LOG("%u timed out waiting for mutex at %p", current->id, mutex);
            pop_specific(&mutex->waiting, current);
            return ETIMEDOUT;
        } else {
            LOG("%u locked mutex at %p", current->id, mutex);
            pop_specific(&threads_ready, current);
        }
    }

    mutex->rec_count++;
    return 0;
}

int pthread_mutex_getprioceiling(const pthread_mutex_t *mutex, int *prioceiling) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    *prioceiling = mutex->prioceiling;
    return 0;
}

int pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int prioceiling, int *old_ceiling) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    CHECK(EXIT_MISC, pthread_mutex_lock(mutex), "Failed to lock mutex");
    *old_ceiling = mutex->prioceiling;
    mutex->prioceiling = prioceiling;
    CHECK(EXIT_MISC, pthread_mutex_unlock(mutex), "Failed to unlock mutex");
    return 0;
}

static int mutex_unlock_noyield(pthread_mutex_t *mutex) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    
    if (current != mutex->locked_by && (mutex->type == PTHREAD_MUTEX_ERRORCHECK ||
        mutex->type == PTHREAD_MUTEX_RECURSIVE || mutex->robust == PTHREAD_MUTEX_ROBUST))
    {
        return EPERM;
    }

    CHECK(EXIT_ILLEGAL, mutex->locked_by == current,
        "%u tried unlocking mutex at %p locked by %u",
        current->id, mutex, mutex->locked_by->id);
    
    LOG("%u unlocking mutex at %p", current->id, mutex);
    mutex->rec_count--;

    if (mutex->type != PTHREAD_MUTEX_RECURSIVE || mutex->rec_count == 0) {
        mutex->locked_by = NULL;

        // Schedule a waiting thread, if any
        if (mutex->waiting.len != 0) {
            mutex->locked_by = pop_random(&mutex->waiting);
            push(&threads_ready, mutex->locked_by);
            LOG("%u waking blocked thread %u", current->id, mutex->locked_by->id);
        }
    }

    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");

    int ret = mutex_unlock_noyield(mutex);

    if (ret != 0) {
        return ret;
    }

    pthread_yield();
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    CHECK(EXIT_ILLEGAL, cond->initialized, "Cond not initialized");

    for (size_t i = 0; i < cond->waiting.len; i++) {
        append(&threads_ready, &cond->waiting);
    }

    pthread_yield();
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    CHECK(EXIT_ILLEGAL, cond->initialized, "Cond not initialized");
    cond->initialized = false;
    return 0;
}

static const pthread_condattr_t pthread_condattr_default = {
    .pshared = PTHREAD_PROCESS_PRIVATE,
    .initialized = true,
    .clock_id = CLOCK_MONOTONIC,
};

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    if (attr == NULL) {
        attr = &pthread_condattr_default;
    }

    CHECK(EXIT_UNSUPPORTED, attr->pshared == PTHREAD_PROCESS_PRIVATE,
        "Only process private threads are supported");
    
    *cond = (pthread_cond_t) {
        .waiting = pthread_empty_list,
        .initialized = true,
    };

    return 0;
}

int pthread_cond_signal(pthread_cond_t *cond) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, cond->initialized, "Cond not initialized");

    // Can signal more threads - just signal one for now
    if (cond->waiting.len != 0) {
        pthread_t popped = pop_random(&cond->waiting);

        if (popped->state_data.cond_mutex->locked_by == NULL) {
            popped->state_data.cond_mutex->locked_by = popped;

            if (!popped->canceled && popped->cancel_state == PTHREAD_CANCEL_ENABLE) {
                push(&threads_ready, popped);
            }
        } else {
            push(&popped->state_data.cond_mutex->waiting, popped);
        }
    }

    pthread_yield();
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t * cond, 
    pthread_mutex_t *mutex, const struct timespec *timeout)
{
    CHECK(EXIT_ILLEGAL, cond->initialized, "Cond not initialized");
    CHECK(EXIT_ILLEGAL, mutex->initialized, "Mutex not initialized");
    CHECK(EXIT_ILLEGAL, mutex->locked_by == current,
        "pthread_cond_timedwait called with mutex locked by other thread");

    LOG("%u timed-waiting on cond %p, releasing mutex %p", current->id, cond, mutex);

    int ret = mutex_unlock_noyield(mutex);
    assert(ret == 0);

    push(&cond->waiting, current);
    push(&threads_ready, current);
    
    current->state_data.cond_mutex = mutex;
    yield(BLOCK_COND_TIMEDWAIT);

    if (mutex->locked_by == current) {
        pop_specific(&threads_ready, current);

        LOG("%u signaled waiting on cond %p, reacquiring mutex %p", current->id, cond, mutex);

        pthread_mutex_lock(mutex);
        return 0;
    } else {
        pop_specific(&cond->waiting, current);

        if (current->canceled && current->cancel_state == PTHREAD_CANCEL_ENABLE && rand_u32(2)) {
            pthread_exit(PTHREAD_CANCELED);
        }

        LOG("%u timed out waiting on cond %p, reacquiring mutex %p", current->id, cond, mutex);

        pthread_mutex_lock(mutex);
        return ETIMEDOUT;
    }
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    mutex_unlock_noyield(mutex);
    current->state_data.cond_mutex = mutex;
    push(&cond->waiting, current);

    if (current->canceled && current->cancel_state == PTHREAD_CANCEL_ENABLE) {
        push(&threads_ready, current);
    }
    
    yield(BLOCK_COND_WAIT);

    if (mutex->locked_by != current && current->canceled &&
        current->cancel_state == PTHREAD_CANCEL_ENABLE && rand_u32(2))
    {
        pop_specific(&cond->waiting, current);
        pthread_exit(PTHREAD_CANCELED);
    }

    return 0;
}

void pthread_testcancel(void) {
    pthread_yield();

    if (current->canceled && rand_u32(2)) {
        pthread_exit(PTHREAD_CANCELED);
        pthread_yield();
    }
}

int pthread_condattr_destroy(pthread_condattr_t *attr) {
    attr->initialized = false;
    return 0;
}

int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared) {
    *pshared = attr->pshared;
    return 0;
}

int pthread_condattr_init(pthread_condattr_t *attr) {
    *attr = pthread_condattr_default;
    return 0;
}

int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared) {
    attr->pshared = pshared;
    return 0;
}

int pthread_condattr_getclock(pthread_condattr_t * attr, clockid_t *clock_id) {
    *clock_id = attr->clock_id;
    return 0;
}

int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id) {
    // TODO: Fail if clock_id is a CPU clock - but how to detect that?
    attr->clock_id = clock_id;
    return 0;
}

int pthread_attr_init(pthread_attr_t *attr) {
    *attr = default_attr;
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr) {
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detach_state) {
    CHECK_RET(EINVAL, detach_state == PTHREAD_CREATE_DETACHED ||
        detach_state == PTHREAD_CREATE_JOINABLE, "Invalid detach state");

    attr->data.detach_state = detach_state;
    return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detach_state) {
    *detach_state = attr->data.detach_state;
    return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guard_size) {
    *guard_size = attr->data.guard_size;
    return 0;
}

int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guard_size) {
    attr->data.guard_size = guard_size;
    return 0;
}

int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inherit_sched) {
    *inherit_sched = attr->data.inherit_sched;
    return 0;
}

int pthread_attr_setinheritsched(pthread_attr_t *attr, int inherit_sched) {
    CHECK(EXIT_ILLEGAL, inherit_sched == PTHREAD_INHERIT_SCHED ||
        inherit_sched == PTHREAD_EXPLICIT_SCHED, "Invalid inherit sched state");

    attr->data.inherit_sched = inherit_sched;
    return 0;
}

int pthread_attr_getschedparam(const pthread_attr_t *attr, struct sched_param *sched_param) {
    *sched_param = attr->data.sched_param;
    return 0;
}

int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *sched_policy) {
    *sched_policy = attr->data.sched_policy;
    return 0;
}

int pthread_attr_setschedparam(pthread_attr_t *attr, const struct sched_param *sched_param) {
    int min = sched_get_priority_min(attr->data.sched_policy);
    int max = sched_get_priority_max(attr->data.sched_policy);
    int priority = sched_param->sched_priority;
    CHECK(EXIT_ILLEGAL, priority >= min && priority <= max,
        "Priority %d was outside bounds for scheduling policy [%d, %d]", priority, min, max);

    attr->data.sched_param = *sched_param;
    return 0;
}

int pthread_attr_setschedpolicy(pthread_attr_t *attr, int sched_policy) {
    int prio = sched_get_priority_min(sched_policy);
    CHECK(EXIT_ILLEGAL, prio != -1, "Invalid scheduling policy: %d", sched_policy);
    attr->data.sched_policy = sched_policy;
    return 0;
}

int pthread_attr_getscope(const pthread_attr_t *attr, int *scope) {
    *scope = attr->data.scope;
    return 0;
}

int pthread_attr_setscope(pthread_attr_t *attr, int scope) {
    CHECK(EXIT_ILLEGAL, scope == PTHREAD_SCOPE_SYSTEM || scope == PTHREAD_SCOPE_PROCESS,
        "Invalid scope: %d", scope);

    attr->data.scope = scope;
    return 0;
}

int pthread_attr_getstackaddr(const pthread_attr_t *attr, void **stack_addr) {
    *stack_addr = attr->data.stack_addr;
    return 0;
}

int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stack_addr) {
    attr->data.stack_addr = stack_addr;
    return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stack_size) {
    *stack_size = attr->data.stack_size;
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stack_size) {
    CHECK(EXIT_ILLEGAL, attr->data.initialized, "Attr not initialized");
    CHECK_RET(EINVAL, stack_size >= PTHREAD_STACK_MIN,
        "Stack size of %zu less than min stack size of %zu", stack_size, (size_t)PTHREAD_STACK_MIN);

    attr->data.stack_size = stack_size;
    return 0;
}

int pthread_attr_getstack(pthread_attr_t *attr, void **stackaddr, size_t *stacksize) {
    CHECK(EXIT_ILLEGAL, attr->data.initialized, "Attr not initialized");
    *stackaddr = attr->data.stack_addr;
    *stacksize = attr->data.stack_size;
    return 0;
}

int pthread_attr_setstack(pthread_attr_t *attr, void *stack_addr, size_t stack_size) {
    CHECK(EXIT_ILLEGAL, attr->data.initialized, "Attr not initialized");
    CHECK_RET(EINVAL, stack_size >= PTHREAD_STACK_MIN, 
        "Stack size of %zu less than min stack size of %zu", stack_size, (size_t)PTHREAD_STACK_MIN);

    attr->data.stack_addr = stack_addr;
    attr->data.stack_size = stack_size;
    return 0;
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
    *attr = thread->attr;

    attr->data.detach_state = thread->detached
        ? PTHREAD_CREATE_DETACHED
        : PTHREAD_CREATE_JOINABLE;

    attr->data.stack_addr = (void*)thread;

    return 0;
}

int pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *attr, int *prioceiling) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    *prioceiling = attr->prioceiling;
    return 0;
}

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    *protocol = attr->protocol;
    return 0;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    *pshared = attr->pshared;
    return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    *type = attr->type;
    return 0;
}

int pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr, int *robust) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    *robust = attr->robust;
    return 0;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
    *attr = pthread_mutexattr_default;
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    attr->initialized = false;
    return 0;
}

int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    attr->prioceiling = prioceiling;
    return 0;
}

int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    CHECK(EXIT_ILLEGAL, protocol == PTHREAD_PRIO_NONE || protocol == PTHREAD_PRIO_INHERIT ||
        protocol == PTHREAD_PRIO_PROTECT, "Invalid mutex protocol: %d", protocol);

    attr->protocol = protocol;
    return 0;
}

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    CHECK(EXIT_ILLEGAL, pshared == PTHREAD_PROCESS_PRIVATE || pshared == PTHREAD_PROCESS_SHARED,
        "Invalid mutex pshared value: %d", pshared);

    attr->pshared = pshared;
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    CHECK_RET(EINVAL, type == PTHREAD_MUTEX_NORMAL || type == PTHREAD_MUTEX_ERRORCHECK ||
        type == PTHREAD_MUTEX_RECURSIVE || type == PTHREAD_MUTEX_DEFAULT,
        "Invalid mutex type: %d", type);

    attr->type = type;
    return 0;
}

int pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robust) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "Mutex attr not initialized");
    CHECK_RET(EINVAL, robust == PTHREAD_MUTEX_STALLED || robust == PTHREAD_MUTEX_ROBUST,    
        "Invalid mutex robustness: %d", robust);

    attr->robust = robust;
    return 0;
}

void pthread_cleanup_push_inner(pthread_cleanup_t *cleanup) {
    pthread_cleanup_t *old = current->cleanup;
    cleanup->prev = old;
    current->cleanup = cleanup;
}

void pthread_cleanup_pop_inner(int execute) {
    CHECK(EXIT_ILLEGAL, current->cleanup != NULL,
        "Tried to pop cleanup, but cleanup stack is empty");

    if (execute) {
        current->cleanup->routine(current->cleanup->arg);
    }

    current->cleanup = current->cleanup->prev;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void*)) {
    size_t id;

    do {
        id = next_key_id++;
    } while (id == 0);

    *key = (pthread_key_t) {
        .id = id,
        .destructor = destructor,
        .initialized = true,
    };

    return 0;
}

int pthread_key_delete(pthread_key_t key) {
    CHECK(EXIT_ILLEGAL, key.initialized, "Key not initialized");
    key.initialized = false;
    return 0;
}

static void tls_insert_base(struct tls *tls, struct tls_entry entry) {
    size_t mask = tls->cap - 1;
    size_t index = entry.id & mask;
    size_t dist = 0;

    for (;;) {
        struct tls_entry *table_entry = &tls->entries[index];

        if (table_entry->id == 0) {
            *table_entry = entry;
            tls->len++;

            break;
        } else if (table_entry->id == entry.id) {
            if (table_entry->value == NULL) {
                tls->len++;
            }

            *table_entry = entry;
            break;
        }

        size_t probe_distance = (index - table_entry->id) & mask;

        if (dist > probe_distance) {
            if (table_entry->value == NULL) {
                *table_entry = entry;
                tls->len++;
            }

            struct tls_entry tmp = *table_entry;
            *table_entry = entry;
            entry = tmp;
            dist = probe_distance;
        }

        index = (index + 1) & mask;
        dist++;
    }
}

static void tls_remove(struct tls *tls, unsigned int id) {
    size_t mask = tls->cap - 1;
    size_t index = id & mask;
    size_t dist = 0;

    for (;;) {
        struct tls_entry *table_entry = &tls->entries[index];

        if (table_entry->id == 0) {
            break;
        } else if (table_entry->id == id) {
            if (table_entry->value != NULL) {
                tls->len--;
            }

            table_entry->value = NULL;
            break;
        }

        size_t probe_distance = (index - table_entry->id) & mask;

        if (dist > probe_distance) {
            break;
        }

        index = (index + 1) & mask;
        dist++;
    }
}

static void tls_grow(struct tls *tls) {
    size_t new_cap = tls->cap * 2;

    if (new_cap < 16) {
        new_cap = 16;
    }

    struct tls new_tls = (struct tls) {
        .entries = malloc(new_cap * sizeof(struct tls_entry)),
        .cap = new_cap,
        .len = 0,
    };

    CHECK(EXIT_ALLOC, new_tls.entries != NULL, "Allocation failed");

    for (size_t i = 0; i < tls->cap; i++) {
        if (tls->entries[i].id != 0) {
            tls_insert_base(&new_tls, tls->entries[i]);
        }
    }

    free(current->tls.entries);
    current->tls = new_tls;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    CHECK(EXIT_ILLEGAL, key.id != 0, "Tried calling setspecific on uninitialized key");

    if (current->tls.cap * HASH_LOAD_NOM <= current->tls.len * HASH_LOAD_DENOM) {
        tls_grow(&current->tls);
    }

    if (value != NULL) {
        tls_insert_base(&current->tls, (struct tls_entry) {
            .id = key.id,
            .value = (void*)value,
            .destructor = key.destructor,
        });
    } else {
        tls_remove(&current->tls, key.id);
    }

    return 0;
}

void *pthread_getspecific(pthread_key_t key) {
    CHECK(EXIT_ILLEGAL, key.id != 0, "Tried calling getspecific on uninitialized key");

    if (current->tls.len == 0) {
        return 0;
    }

    size_t mask = current->tls.cap - 1;
    size_t index = key.id & mask;
    size_t dist = 0;

    for (;;) {
        struct tls_entry entry = current->tls.entries[index];
        size_t probe_distance = (index - entry.id) & mask;

        if (entry.id == key.id) {
            return entry.value;
        } else if (entry.id == 0 || probe_distance <= dist) {
            return NULL;
        }

        dist++;
        index++;
        index &= mask;
    }
}

static const pthread_rwlockattr_t pthread_rwlockattr_default = {
    .pshared = PTHREAD_PROCESS_PRIVATE,
    .initialized = true,
};

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr) {
    attr->initialized = false;
    return 0;
}

int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr, int *pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "rwlockattr not initialized");
    *pshared = attr->pshared;
    return 0;
}

int pthread_rwlockattr_init(pthread_rwlockattr_t *attr) {
    *attr = pthread_rwlockattr_default;
    return 0;
}

int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "rwlockattr not initialized");

    CHECK(EXIT_ILLEGAL, pshared == PTHREAD_PROCESS_PRIVATE || pshared == PTHREAD_PROCESS_SHARED,
        "rwlockattr pshared set to invalid value: %d", pshared);

    attr->pshared = pshared;
    return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr) {
    if (attr == NULL) {
        attr = &pthread_rwlockattr_default;
    }

    CHECK(EXIT_ILLEGAL, attr->initialized, "rwlockattr not initialized");
    CHECK(EXIT_ILLEGAL, attr->pshared == PTHREAD_PROCESS_PRIVATE,
        "Only process private rwlock supported");

    *rwlock = (pthread_rwlock_t) {
        .writer = NULL,
        .pending_readers = pthread_empty_list,
        .pending_writers = pthread_empty_list,
        .initialized = true,
    };

    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    CHECK(EXIT_ILLEGAL, rwlock->writer == NULL,
        "Tried to destroy locked rwlock with active writer");
    CHECK(EXIT_ILLEGAL, rwlock->readers.len == 0,
        "Tried to destroy locked rwlock with active reader");
    
    *rwlock = (pthread_rwlock_t) {
        .initialized = false,
    };

    return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    if (rwlock->writer != NULL) {
        push(&rwlock->pending_readers, current);
        current->state_data.rwlock_reader = false;
        yield(BLOCK_RWLOCK_RDLOCK);
    } else {
        multiset_insert(&rwlock->readers, current);
    }

    pthread_yield();

    return 0;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    if (rwlock->writer != NULL || rwlock->readers.len != 0) {
        push(&rwlock->pending_writers, current);
        yield(BLOCK_RWLOCK_WRLOCK);
        assert(rwlock->writer == current);
    } else {
        rwlock->writer = current;
    }

    pthread_yield();

    return 0;
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock, const struct timespec *time) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    if (rwlock->writer != NULL) {
        push(&rwlock->pending_readers, current);
        push(&threads_ready, current);
        current->state_data.rwlock_reader = false;
        yield(BLOCK_RWLOCK_TIMEDRDLOCK);
        
        if (current->state_data.rwlock_reader) {
            pop_specific(&threads_ready, current);
        } else {
            pop_specific(&rwlock->pending_writers, current);
            return ETIMEDOUT;
        }
    }

    multiset_insert(&rwlock->readers, current);
    rwlock->writer = current;

    return 0;
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock, const struct timespec *time) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    if (rwlock->writer != NULL || rwlock->readers.len != 0) {
        push(&rwlock->pending_writers, current);
        push(&threads_ready, current);
        yield(BLOCK_RWLOCK_TIMEDWRLOCK);
        
        if (rwlock->writer == current) {
            pop_specific(&threads_ready, current);
        } else {
            pop_specific(&rwlock->pending_writers, current);
            return ETIMEDOUT;
        }
    }

    rwlock->writer = current;
    return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");

    if (rwlock->writer != NULL) {
        return EBUSY;
    }

    multiset_insert(&rwlock->readers, current);
    pthread_yield();
    return 0;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");

    if (rwlock->writer != NULL || rwlock->readers.len != 0) {
        return EBUSY;
    }

    rwlock->writer = current;
    pthread_yield();
    return 0;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
    pthread_yield();

    CHECK(EXIT_ILLEGAL, rwlock->initialized, "rwlock not initialized");
    if (rwlock->writer != NULL) {
        CHECK(EXIT_ILLEGAL, rwlock->writer == current,
            "%u tried unlocking rwlock at %p, but %u has a write lock", current->id, rwlock,
            rwlock->writer->id);

        rwlock->writer = NULL;

        bool pending_writers = rwlock->pending_writers.len != 0;
        bool pending_readers = rwlock->pending_readers.len != 0;

        if (pending_readers || pending_writers) {
            if (pending_readers && pending_writers ? rand_u32(2) : pending_writers) {
                rwlock->writer = pop_random(&rwlock->pending_writers);
                push(&threads_ready, rwlock->writer);
            } else {
                append(&threads_ready, &rwlock->pending_readers);

                pthread_t *pending_readers = threads_ptr(&rwlock->pending_readers);
                for (size_t i = 0; i < rwlock->pending_readers.len; i++) {
                    multiset_insert(&rwlock->readers, pending_readers[i]);
                }

                rwlock->pending_readers.len = 0;
            }
        }
    } else {
        CHECK(EXIT_ILLEGAL, multiset_remove(&rwlock->readers, current),
            "%u called pthread_rwlock_unlock, but holds no read or write lock", current->id);

        if (rwlock->readers.len == 0 && rwlock->pending_writers.len != 0) {
            rwlock->writer = pop_random(&rwlock->pending_writers);
            push(&threads_ready, rwlock->writer);
        }
    }

    pthread_yield();

    return 0;
}

int pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param) {
    *policy = thread->sched_policy;
    *param = thread->sched_param;
    return 0;
}

int pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param) {
    thread->sched_policy = policy;
    thread->sched_param = *param;
    return 0;
}

static const pthread_barrierattr_t barrierattr_default = {
    .initialized = true,
    .pshared = PTHREAD_PROCESS_PRIVATE,
};

int pthread_barrierattr_init(pthread_barrierattr_t *attr) {
    *attr = barrierattr_default;
    return 0;
}

int pthread_barrierattr_destroy(pthread_barrierattr_t *attr) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "barrierattr not initialized");
    attr->initialized = false;
    return 0;
}

int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr, int *pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "barrierattr not initialized");
    *pshared = attr->pshared;
    return 0;
}

int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared) {
    CHECK(EXIT_ILLEGAL, attr->initialized, "barrierattr not initialized");
    CHECK(EXIT_ILLEGAL, pshared == PTHREAD_PROCESS_PRIVATE ||
        pshared == PTHREAD_PROCESS_SHARED, "Barrier pshared set to invalid value: %d", pshared);

    attr->pshared = pshared;
    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier) {
    CHECK(EXIT_ILLEGAL, barrier->initialized, "barrier not initialized");
    barrier->initialized = false;
    return 0;
}

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr,
    unsigned count)
{
    if (attr == NULL) {
        attr = &barrierattr_default;
    }

    CHECK(EXIT_ILLEGAL, attr->initialized, "barrierattr not initialized");
    CHECK(EXIT_UNSUPPORTED, attr->pshared == PTHREAD_PROCESS_PRIVATE, 
        "System-shared barriers are not supported");
    CHECK_RET(EINVAL, count > 0, "Barrier count must be non-zero");

    *barrier = (pthread_barrier_t) {
        .initialized = true,
        .count = count,
        .waiting = pthread_empty_list,
    };

    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier) {
    pthread_yield();
    
    current->state_data.barrier_serial = false;
    push(&barrier->waiting, current);

    if (barrier->waiting.len == barrier->count) {
        pthread_t serial = pop_random(&barrier->waiting);
        serial->state_data.barrier_serial = true;
        push(&threads_ready, serial);

        append(&threads_ready, &barrier->waiting);

        LOG("%u completed barrier at %p (%zu) - %u got serial", current->id, barrier,
            barrier->count, serial->id);
    } else {
        LOG("%u waiting on barrier at %p (%zu/%zu)", current->id, barrier, barrier->waiting.len,
            barrier->count);
    }

    yield(BLOCK_BARRIER_WAIT);

    return current->state_data.barrier_serial
        ? PTHREAD_BARRIER_SERIAL_THREAD
        : 0;

    return 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, int pshared) {
    CHECK(EXIT_UNSUPPORTED, pshared == PTHREAD_PROCESS_PRIVATE,
        "Only process private spinlocks are supported");

    pthread_mutex_init(&lock->mutex, NULL);
    return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock) {
    return pthread_mutex_destroy(&lock->mutex);
}

int pthread_spin_lock(pthread_spinlock_t *lock) {
    return pthread_mutex_lock(&lock->mutex);
}

int pthread_spin_trylock(pthread_spinlock_t *lock) {
    return pthread_mutex_trylock(&lock->mutex);
}

int pthread_spin_unlock(pthread_spinlock_t *lock) {
    return pthread_mutex_unlock(&lock->mutex);
}

int pthread_getcpuclockid(pthread_t thread, clockid_t *clockid) {
    return CLOCK_MONOTONIC;
}

int pthread_setschedprio(pthread_t thread, int prio) {
    thread->sched_param.sched_priority = prio;
    return 0;
}

static const int valid_signals[] = {
    SIGABRT, SIGALRM, SIGBUS, SIGCHLD, SIGCLD, SIGCONT, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGIO,
    SIGIOT, SIGKILL, SIGPIPE, SIGPOLL, SIGPROF, SIGPWR, SIGQUIT, SIGSEGV, SIGSTKFLT, SIGSTOP,
    SIGTSTP, SIGSYS, SIGTERM, SIGTRAP, SIGTTIN, SIGTTOU, SIGURG, SIGUSR1, SIGUSR2, SIGVTALRM,
    SIGXCPU, SIGXFSZ, SIGWINCH
};

int pthread_kill(pthread_t thread, int sig) {
    if (sig != 0) {
        for (size_t i = 0;; i++) {
            CHECK_RET(EINVAL, i < sizeof(valid_signals) / sizeof(*valid_signals),
                "Invalid signal to pthread_kill: %d", sig);
            
            if (sig == valid_signals[i]) {
                break;
            }
        }

        CHECK(EXIT_UNSUPPORTED, false, "pthread_kill is not supported");
    }

    return 0;
}

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    pthread_yield();

    if (*once_control == 1) {
        *once_control = 2;
        init_routine();
        pthread_yield();
    } else {
        CHECK(EXIT_ILLEGAL, *once_control == 2, "pthread_once on uninitialized pthread_once_t");
   }

   return 0;
}

static int concurrency = 1;

int pthread_getconcurrency() {
    return concurrency;
}

int pthread_setconcurrency(int new_level) {
    CHECK_RET(EINVAL, new_level >= 0, "setconcurrency called with negative level: %d", new_level);
    concurrency = new_level;
    return 0;
}