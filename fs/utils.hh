#ifndef FS_FUZZ_UTILS_HH
#define FS_FUZZ_UTILS_HH

#include <stdio.h>
#include <stdlib.h>

#define FATAL(...) do { \
  fprintf(stderr, __VA_ARGS__); \
  fprintf(stderr, "\nLocation: %s(), %s:%u\n", \
      __FUNCTION__, __FILE__, __LINE__); \
  exit(1); \
 } while (0)

#endif
