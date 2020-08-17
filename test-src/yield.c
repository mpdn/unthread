#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

/*
BEGIN_TEST_SPEC
["1", "2"]
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
  pthread_t a, b;
  pthread_create(&a, NULL, incr, NULL);
  pthread_create(&b, NULL, incr, NULL);
  pthread_join(a, NULL);
  pthread_join(b, NULL);
  printf("%d", val);

  return 0;
}