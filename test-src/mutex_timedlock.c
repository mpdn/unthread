#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
BEGIN_TEST_SPEC
["ETIMEDOUT", ""]
END_TEST_SPEC
*/

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* start(void* arg) {
    pthread_mutex_lock(&mutex);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

int main() {
    struct timespec ts;
    ts.tv_nsec = 0;
    ts.tv_sec = 1;

    pthread_t a;
    pthread_create(&a, NULL, start, NULL);

    switch (pthread_mutex_timedlock(&mutex, &ts)) {
        case ETIMEDOUT:
            printf("ETIMEDOUT");
            break;
        case 0:
            pthread_mutex_unlock(&mutex);
            break;
        default:
            printf("Unexpected result");
            return 1;
    }

    pthread_join(a, NULL);
    return 0;
}