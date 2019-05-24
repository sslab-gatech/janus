/*
 * Copyright (c) 2006-2018 Luben Tuikov and Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */
#endif
#endif

/*
 * This utility issues the SCSI WRITE BUFFER command to the given device.
 */

static const char * version_str = "1.24 20180111";    /* spc5r18 */

#define ME "sg_write_buffer: "
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define EBUFF_SZ 256

#define WRITE_BUFFER_CMD 0x3b
#define WRITE_BUFFER_CMDLEN 10
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT 300      /* 300 seconds, 5 minutes */

static struct option long_options[] = {
        {"bpw", required_argument, 0, 'b'},
        {"dry-run", no_argument, 0, 'd'},
        {"dry_run", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"id", required_argument, 0, 'i'},
        {"in", required_argument, 0, 'I'},
        {"length", required_argument, 0, 'l'},
        {"mode", required_argument, 0, 'm'},
        {"offset", required_argument, 0, 'o'},
        {"read-stdin", no_argument, 0, 'r'},
        {"read_stdin", no_argument, 0, 'r'},
        {"raw", no_argument, 0, 'r'},
        {"skip", required_argument, 0, 's'},
        {"specific", required_argument, 0, 'S'},
        {"timeout", required_argument, 0, 't' },
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_write_buffer [--bpw=CS] [--dry-run] [--help] [--id=ID] "
            "[--in=FILE]\n"
            "                       [--length=LEN] [--mode=MO] "
            "[--offset=OFF]\n"
            "                       [--read-stdin] [--skip=SKIP] "
            "[--specific=MS]\n"
            "                       [--timeout=TO] [--verbose] [--version] "
            "DEVICE\n"
            "  where:\n"
            "    --bpw=CS|-b CS         CS is chunk size: bytes per write "
            "buffer\n"
            "                           command (def: 0 -> as many as "
            "possible)\n"
            "    --dry-run|-d           skip WRITE BUFFER commands, do "
            "everything else\n"
            "    --help|-h              print out usage message then exit\n"
            "    --id=ID|-i ID          buffer identifier (0 (default) to "
            "255)\n"
            "    --in=FILE|-I FILE      read from FILE ('-I -' read "
            "from stdin)\n"
            "    --length=LEN|-l LEN    length in bytes to write; may be "
            "deduced from\n"
            "                           FILE\n"
            "    --mode=MO|-m MO        write buffer mode, MO is number or "
            "acronym\n"
            "                           (def: 0 -> 'combined header and "
            "data' (obs))\n"
            "    --offset=OFF|-o OFF    buffer offset (unit: bytes, def: 0)\n"
            "    --read-stdin|-r        read from stdin (same as '-I -')\n"
            "    --skip=SKIP|-s SKIP    bytes in file FILE to skip before "
            "reading\n"
            "    --specific=MS|-S MS    mode specific value; 3 bit field "
            "(0 to 7)\n"
            "    --timeout=TO|-t TO     command timeout in seconds (def: "
            "300)\n"
            "    --verbose|-v           increase verbosity\n"
            "    --version|-V           print version string and exit\n\n"
            "Performs one or more SCSI WRITE BUFFER commands. Use '-m xxx' "
            "to list\navailable modes. A chunk size of 4 KB ('--bpw=4k') "
            "seems to work well.\nExample: sg_write_buffer -b 4k -I xxx.lod "
            "-m 7 /dev/sg3\n"
          );

}

#define MODE_HEADER_DATA        0
#define MODE_VENDOR             1
#define MODE_DATA               2
#define MODE_DNLD_MC            4
#define MODE_DNLD_MC_SAVE       5
#define MODE_DNLD_MC_OFFS       6
#define MODE_DNLD_MC_OFFS_SAVE  7
#define MODE_ECHO_BUFFER        0x0A
#define MODE_DNLD_MC_EV_OFFS_DEFER 0x0D
#define MODE_DNLD_MC_OFFS_DEFER 0x0E
#define MODE_ACTIVATE_MC        0x0F
#define MODE_EN_EX_ECHO         0x1A
#define MODE_DIS_EX             0x1B
#define MODE_DNLD_ERR_HISTORY   0x1C


struct mode_s {
        const char *mode_string;
        int   mode;
        const char *comment;
};

static struct mode_s mode_arr[] = {
        {"hd",         MODE_HEADER_DATA, "combined header and data "
                "(obsolete)"},
        {"vendor",     MODE_VENDOR,    "vendor specific"},
        {"data",       MODE_DATA,      "data"},
        {"dmc",        MODE_DNLD_MC,   "download microcode and activate"},
        {"dmc_save",   MODE_DNLD_MC_SAVE, "download microcode, save and "
                "activate"},
        {"dmc_offs",   MODE_DNLD_MC_OFFS, "download microcode with offsets "
                "and activate"},
        {"dmc_offs_save", MODE_DNLD_MC_OFFS_SAVE, "download microcode with "
                "offsets, save and\n\t\t\t\tactivate"},
        {"echo",       MODE_ECHO_BUFFER, "write data to echo buffer"},
        {"dmc_offs_ev_defer", MODE_DNLD_MC_EV_OFFS_DEFER, "download "
                "microcode with offsets, select\n\t\t\t\tactivation event, "
                "save and defer activation"},
        {"dmc_offs_defer", MODE_DNLD_MC_OFFS_DEFER, "download microcode "
                "with offsets, save and\n\t\t\t\tdefer activation"},
        {"activate_mc", MODE_ACTIVATE_MC, "activate deferred microcode"},
        {"en_ex",      MODE_EN_EX_ECHO, "enable expander communications "
                "protocol and\n\t\t\t\techo buffer (obsolete)"},
        {"dis_ex",     MODE_DIS_EX, "disable expander communications "
                "protocol\n\t\t\t\t(obsolete)"},
        {"deh",        MODE_DNLD_ERR_HISTORY, "download application client "
                "error history "},
        {NULL, 0, NULL},
};

static void
print_modes(void)
{
    const struct mode_s * mp;

    pr2serr("The modes parameter argument can be numeric (hex or decimal)\n"
            "or symbolic:\n");
    for (mp = mode_arr; mp->mode_string; ++mp) {
        pr2serr(" %2d (0x%02x)  %-18s%s\n", mp->mode, mp->mode,
                mp->mode_string, mp->comment);
    }
    pr2serr("\nAdditionally '--bpw=<val>,act' does a activate deferred "
            "microcode after\nsuccessful dmc_offs_defer and "
            "dmc_offs_ev_defer mode downloads.\n");
}


int
main(int argc, char * argv[])
{
    bool bpw_then_activate = false;
    bool dry_run = false;
    bool got_stdin = false;
    bool wb_len_given = false;
    int sg_fd, infd, res, c, len, k, n;
    int bpw = 0;
    int do_help = 0;
    int ret = 0;
    int verbose = 0;
    int wb_id = 0;
    int wb_len = 0;
    int wb_mode = 0;
    int wb_offset = 0;
    int wb_skip = 0;
    int wb_timeout = DEF_PT_TIMEOUT;
    int wb_mspec = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    unsigned char * dop = NULL;
    char * cp;
    const struct mode_s * mp;
    char ebuff[EBUFF_SZ];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:dhi:I:l:m:o:rs:S:t:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bpw = sg_get_num(optarg);
            if (bpw < 0) {
                pr2serr("argument to '--bpw' should be in a positive "
                        "number\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((cp = strchr(optarg, ','))) {
                if (0 == strncmp("act", cp + 1, 3))
                    bpw_then_activate = true;
            }
            break;
        case 'd':
            dry_run = true;
            break;
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'i':
            wb_id = sg_get_num(optarg);
            if ((wb_id < 0) || (wb_id > 255)) {
                pr2serr("argument to '--id' should be in the range 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            file_name = optarg;
            break;
        case 'l':
            wb_len = sg_get_num(optarg);
            if (wb_len < 0) {
                pr2serr("bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             wb_len_given = true;
             break;
        case 'm':
            if (isdigit(*optarg)) {
                wb_mode = sg_get_num(optarg);
                if ((wb_mode < 0) || (wb_mode > 31)) {
                    pr2serr("argument to '--mode' should be in the range 0 "
                            "to 31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (mp = mode_arr; mp->mode_string; ++mp) {
                    if (0 == strncmp(mp->mode_string, optarg, len)) {
                        wb_mode = mp->mode;
                        break;
                    }
                }
                if (! mp->mode_string) {
                    print_modes();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            break;
        case 'o':
           wb_offset = sg_get_num(optarg);
           if (wb_offset < 0) {
                pr2serr("bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':       /* --read-stdin and --raw (previous name) */
            file_name = "-";
            break;
        case 's':
           wb_skip = sg_get_num(optarg);
           if (wb_skip < 0) {
                pr2serr("bad argument to '--skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'S':
            wb_mspec = sg_get_num(optarg);
            if ((wb_mspec < 0) || (wb_mspec > 7)) {
                pr2serr("expected argument to '--specific' to be 0 to 7\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 't':
            wb_timeout = sg_get_num(optarg);
            if (wb_timeout < 0) {
                pr2serr("Invalid argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_help) {
        if (do_help > 1) {
            usage();
            pr2serr("\n");
            print_modes();
        } else
            usage();
        return 0;
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((wb_len > 0) && (bpw > wb_len)) {
        pr2serr("trim chunk size (CS) to be the same as LEN\n");
        bpw = wb_len;
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (file_name || (wb_len > 0)) {
        if (0 == wb_len)
            wb_len = DEF_XFER_LEN;
        if (NULL == (dop = (unsigned char *)malloc(wb_len))) {
            pr2serr(ME "out of memory\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        memset(dop, 0xff, wb_len);
        if (file_name) {
            got_stdin = (0 == strcmp(file_name, "-"));
            if (got_stdin) {
                if (wb_skip > 0) {
                    pr2serr("Can't skip on stdin\n");
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                }
                infd = STDIN_FILENO;
            } else {
                if ((infd = open(file_name, O_RDONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for reading", file_name);
                    perror(ebuff);
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                } else if (sg_set_binary_mode(infd) < 0)
                    perror("sg_set_binary_mode");
                if (wb_skip > 0) {
                    if (lseek(infd, wb_skip, SEEK_SET) < 0) {
                        snprintf(ebuff,  EBUFF_SZ, ME "couldn't skip to "
                                 "required position on %s", file_name);
                        perror(ebuff);
                        close(infd);
                        ret = SG_LIB_FILE_ERROR;
                        goto err_out;
                    }
                }
            }
            res = read(infd, dop, wb_len);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                         file_name);
                perror(ebuff);
                if (! got_stdin)
                    close(infd);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            if (res < wb_len) {
                if (wb_len_given) {
                    pr2serr("tried to read %d bytes from %s, got %d bytes\n",
                            wb_len, file_name, res);
                    pr2serr("pad with 0xff bytes and continue\n");
                } else {
                    if (verbose) {
                        pr2serr("tried to read %d bytes from %s, got %d "
                                "bytes\n", wb_len, file_name, res);
                        pr2serr("will write %d bytes", res);
                        if ((bpw > 0) && (bpw < wb_len))
                            pr2serr(", %d bytes per WRITE BUFFER command\n",
                                    bpw);
                        else
                            pr2serr("\n");
                    }
                    wb_len = res;
                }
            }
            if (! got_stdin)
                close(infd);
        }
    }

    res = 0;
    if (bpw > 0) {
        for (k = 0; k < wb_len; k += n) {
            n = wb_len - k;
            if (n > bpw)
                n = bpw;
            if (verbose)
                pr2serr("sending write buffer, mode=0x%x, mspec=%d, id=%d, "
                        " offset=%d, len=%d\n", wb_mode, wb_mspec, wb_id,
                        wb_offset + k, n);
            if (dry_run) {
                if (verbose)
                    pr2serr("skipping WRITE BUFFER command due to "
                            "--dry-run\n");
                res = 0;
            } else
                res = sg_ll_write_buffer_v2(sg_fd, wb_mode, wb_mspec, wb_id,
                                            wb_offset + k, dop + k, n,
                                            wb_timeout, true, verbose);
            if (res)
                break;
        }
        if (bpw_then_activate) {
            if (verbose)
                pr2serr("sending Activate deferred microcode [0xf]\n");
            if (dry_run) {
                if (verbose)
                    pr2serr("skipping WRITE BUFFER(ACTIVATE) command due to "
                            "--dry-run\n");
                res = 0;
            } else
                res = sg_ll_write_buffer_v2(sg_fd, MODE_ACTIVATE_MC,
                                            0 /* buffer_id */,
                                            0 /* buffer_offset */, 0,
                                            NULL, 0, wb_timeout, true,
                                            verbose);
        }
    } else {
        if (verbose)
            pr2serr("sending single write buffer, mode=0x%x, mpsec=%d, "
                    "id=%d, offset=%d, len=%d\n", wb_mode, wb_mspec, wb_id,
                    wb_offset, wb_len);
        if (dry_run) {
            if (verbose)
                pr2serr("skipping WRITE BUFFER(all in one) command due to "
                        "--dry-run\n");
            res = 0;
        } else
            res = sg_ll_write_buffer_v2(sg_fd, wb_mode, wb_mspec, wb_id,
                                        wb_offset, dop, wb_len, wb_timeout,
                                        true, verbose);
    }
    if (0 != res) {
        char b[80];

        ret = res;
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Write buffer failed: %s\n", b);
    }

err_out:
    if (dop)
        free(dop);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
