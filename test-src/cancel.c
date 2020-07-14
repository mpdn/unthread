#include <stdio.h>
#include <pthread.h>

/*
BEGIN_TEST_SPEC
["NOT CANCELED", ""]
END_TEST_SPEC
*/

int main() {
    pthread_cancel(pthread_self());
    pthread_testcancel();
    printf("NOT CANCELED");
    return 0;
}