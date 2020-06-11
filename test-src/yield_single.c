#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

/*
BEGIN_TEST_SPEC
[
    {"stdout": "1"},
    {"stdout": "2"}
]
END_TEST_SPEC
*/

static int val = 0;

void* incr(void* arg) {
    int v;
    
    v = val;

    pthread_yield();

    val = v + 1;

    return NULL;
}

int main() {
    pthread_t a;
    pthread_create(&a, NULL, incr, NULL);
    incr(NULL);
    pthread_join(a, NULL);
    printf("%d", val);
    
    return 0;
}