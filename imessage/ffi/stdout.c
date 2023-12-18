#include <stdio.h>

typedef void (*stdout_callback_t)(const char *, int);

void stdout_write(stdout_callback_t callback, const char *data, int n) {
  callback(data, n);
}
