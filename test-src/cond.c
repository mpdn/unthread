#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

/*
BEGIN_TEST_SPEC
[""]
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
    pthread_t a;
    pthread_mutex_lock(&mutex);
    pthread_create(&a, NULL, foo, NULL);
    pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    pthread_join(a, NULL);
    
    return 0;
}