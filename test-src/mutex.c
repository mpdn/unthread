#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

/*
BEGIN_TEST_SPEC
["1", "2"]
END_TEST_SPEC
*/

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