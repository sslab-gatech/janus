#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "f2fs_fuzzer.hh"

extern "C" void compress(const char *input_path, void *buffer, const char *meta_path)
{
  f2fs_fuzzer.compress(input_path, buffer, meta_path);
}

extern "C" void decompress(const void *mem, size_t len)
{
  f2fs_fuzzer.decompress(mem, len, true);
}

extern "C" void sync_to_file(const char *path)
{
  f2fs_fuzzer.sync_to_file(path);
}
