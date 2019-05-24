/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

#define _RET_IP_ (unsigned long)__builtin_return_address(0)

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE] = {0,};
u8* __afl_area_ptr = __afl_area_initial;
u16 __afl_prev_loc = 0;
u32 __afl_in_trace = 0;

// unsigned long __afl_prev_loc;
// FILE *fout;

/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);
     
    /* Once woken up, create a clone of our process. */

    child_pid = fork();
    if (child_pid < 0) _exit(1);

    /* In child process: close fds, resume execution. */

    if (!child_pid) {

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      return;
  
    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, 0) < 0) _exit(1);

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}

/* attach to image buffer */
static void __attach_image_buffer(void **buffer, size_t *size) {

  char *shm_name = getenv("SHAREMEMPATH");
  size_t shm_size = strtoul(getenv("SHAREMEMSIZE"), NULL, 10);

  int fd = shm_open(shm_name, O_RDONLY, 0666);
  if (fd < 0) _exit(1);

  void *shm_buffer = mmap(NULL, shm_size, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_buffer == MAP_FAILED) {
    perror("mmap()");
    _exit(1);
  }

  close(fd);

  *buffer = shm_buffer;
  *size = shm_size;

}

/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void **buffer, size_t *size) {

  static u8 init_done;

  if (!init_done) {
    if (buffer != NULL)
      __attach_image_buffer(buffer, size); 
    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;
  }

}

void __afl_manual_init_syscall(void) {

  static u8 init_done;

  if (!init_done) {
    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;
  }

}


/*
void __sanitizer_cov_trace_pc() {
  unsigned long location = _RET_IP_;
  log_addr(location);
  ++__afl_area_ptr[(location ^ __afl_prev_loc) & (MAP_SIZE - 1)];
  __afl_prev_loc = location >> 1;
}
*/
