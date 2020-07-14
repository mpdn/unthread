#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>

/*
BEGIN_TEST_SPEC
["", "ETIMEDOUT"]
END_TEST_SPEC
*/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void* foo(void* arg) {
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

int main() {
    struct timespec ts;
    ts.tv_nsec = 0;
    ts.tv_sec = 1;

    pthread_t a;
    pthread_mutex_lock(&mutex);
    pthread_create(&a, NULL, foo, NULL);

    switch (pthread_cond_timedwait(&cond, &mutex, &ts)) {
        case ETIMEDOUT:
            printf("ETIMEDOUT");
            break;
        case 0:
            break;
        default:
            printf("Unexpected result");
            return 1;
    }

    pthread_mutex_unlock(&mutex);
    pthread_join(a, NULL);
    return 0;
}