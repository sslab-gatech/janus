/*
 * Copyright (c) 2009-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_pt_nvme.h"


static const char * scsi_pt_version_str = "3.03 20180115";

static const char * nvme_scsi_vendor_str = "NVMe    ";


const char *
scsi_pt_version()
{
    return scsi_pt_version_str;
}

/* Given the NVMe Identify controller response and optionally the NVMe
 * Identify namespace response (NULL otherwise), generate the SCSI VPD
 * page 0x83 (device identification) descriptor(s) in dop. Return the
 * number of bytes written which will not exceed max_do_len. Probably use
 * Peripheral Device Type (pdt) of 0 (disk) for don't know. Transport
 * protocol (tproto) should be -1 if not known, else SCSI value.
 * N.B. Does not write total VPD page length into dop[2:3] . */
int
sg_make_vpd_devid_for_nvme(const uint8_t * nvme_id_ctl_p,
                           const uint8_t * nvme_id_ns_p, int pdt,
                           int tproto, uint8_t * dop, int max_do_len)
{
    bool have_nguid, have_eui64;
    int k, n;
    char b[4];

    if ((NULL == nvme_id_ctl_p) || (NULL == dop) || (max_do_len < 56))
        return 0;

    memset(dop, 0, max_do_len);
    dop[0] = 0x1f & pdt;  /* (PQ=0)<<5 | (PDT=pdt); 0 or 0xd (SES) */
    dop[1] = 0x83;      /* Device Identification VPD page number */
    /* Build a T10 Vendor ID based designator (desig_id=1) for controller */
    if (tproto >= 0) {
        dop[4] = ((0xf & tproto) << 4) | 0x2;
        dop[5] = 0xa1; /* PIV=1, ASSOC=2 (target device), desig_id=1 */
    } else {
        dop[4] = 0x2;  /* Prococol id=0, code_set=2 (ASCII) */
        dop[5] = 0x21; /* PIV=0, ASSOC=2 (target device), desig_id=1 */
    }
    memcpy(dop + 8, nvme_scsi_vendor_str, 8); /* N.B. this is "NVMe    " */
    memcpy(dop + 16, nvme_id_ctl_p + 24, 40);  /* MN */
    for (k = 40; k > 0; --k) {
        if (' ' == dop[15 + k])
            dop[15 + k] = '_'; /* convert trailing spaces */
        else
            break;
    }
    if (40 == k)
        --k;
    n = 16 + 1 + k;
    if (max_do_len < (n + 20))
        return 0;
    memcpy(dop + n, nvme_id_ctl_p + 4, 20); /* SN */
    for (k = 20; k > 0; --k) {  /* trim trailing spaces */
        if (' ' == dop[n + k - 1])
            dop[n + k - 1] = '\0';
        else
            break;
    }
    n += k;
    if (0 != (n % 4))
        n = ((n / 4) + 1) * 4;  /* round up to next modulo 4 */
    dop[7] = n - 8;
    if (NULL == nvme_id_ns_p)
        return n;

    /* Look for NGUID (16 byte identifier) or EUI64 (8 byte) fields in
     * NVME Identify for namespace. If found form a EUI and a SCSI string
     * descriptor for non-zero NGUID or EUI64 (prefer NGUID if both). */
    have_nguid = ! sg_all_zeros(nvme_id_ns_p + 104, 16);
    have_eui64 = ! sg_all_zeros(nvme_id_ns_p + 120, 8);
    if ((! have_nguid) && (! have_eui64))
        return n;
    if (have_nguid) {
        if (max_do_len < (n + 20))
            return n;
        dop[n + 0] = 0x1;  /* Prococol id=0, code_set=1 (binary) */
        dop[n + 1] = 0x02; /* PIV=0, ASSOC=0 (lu), desig_id=2 (eui) */
        dop[n + 3] = 16;
        memcpy(dop + n + 4, nvme_id_ns_p + 104, 16);
        n += 20;
        if (max_do_len < (n + 40))
            return n;
        dop[n + 0] = 0x3;  /* Prococol id=0, code_set=3 (utf8) */
        dop[n + 1] = 0x08; /* PIV=0, ASSOC=0 (lu), desig_id=8 (scsi string) */
        dop[n + 3] = 36;
        memcpy(dop + n + 4, "eui.", 4);
        for (k = 0; k < 16; ++k) {
            snprintf(b, sizeof(b), "%02X", nvme_id_ns_p[104 + k]);
            memcpy(dop + n + 8 + (2 * k), b, 2);
        }
        return n + 40;
    } else {    /* have_eui64 is true, 8 byte identifier */
        if (max_do_len < (n + 12))
            return n;
        dop[n + 0] = 0x1;  /* Prococol id=0, code_set=1 (binary) */
        dop[n + 1] = 0x02; /* PIV=0, ASSOC=0 (lu), desig_id=2 (eui) */
        dop[n + 3] = 8;
        memcpy(dop + n + 4, nvme_id_ns_p + 120, 8);
        n += 12;
        if (max_do_len < (n + 24))
            return n;
        dop[n + 0] = 0x3;  /* Prococol id=0, code_set=3 (utf8) */
        dop[n + 1] = 0x08; /* PIV=0, ASSOC=0 (lu), desig_id=8 (scsi string) */
        dop[n + 3] = 20;
        memcpy(dop + n + 4, "eui.", 4);
        for (k = 0; k < 8; ++k) {
            snprintf(b, sizeof(b), "%02X", nvme_id_ns_p[120 + k]);
            memcpy(dop + n + 8 + (2 * k), b, 2);
        }
        return n + 24;
    }
}
