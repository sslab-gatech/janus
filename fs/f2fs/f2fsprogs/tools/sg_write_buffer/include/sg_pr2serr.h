#ifndef SG_PR2SERR_H
#define SG_PR2SERR_H

/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__GNUC__) || defined(__clang__)
int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
int pr2serr(const char * fmt, ...);
#endif


#ifdef __cplusplus
}
#endif

#endif
