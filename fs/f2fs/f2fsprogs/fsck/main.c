/**
 * main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2015 Jaegeuk Kim <jaegeuk@kernel.org>
 *  : implement defrag.f2fs
 * Copyright (C) 2015 Huawei Ltd.
 *   Hou Pengyang <houpengyang@huawei.com>
 *   Liu Shuoran <liushuoran@huawei.com>
 *   Jaegeuk Kim <jaegeuk@kernel.org>
 *  : add sload.f2fs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"
#include <libgen.h>
#include <ctype.h>
#include <getopt.h>
#include "quotaio.h"

struct f2fs_fsck gfsck;

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
extern struct sparse_file *f2fs_sparse_file;
#endif

static char *absolute_path(const char *file)
{
	char *ret;
	char cwd[PATH_MAX];

	if (file[0] != '/') {
		if (getcwd(cwd, PATH_MAX) == NULL) {
			fprintf(stderr, "Failed to getcwd\n");
			exit(EXIT_FAILURE);
		}
		ret = malloc(strlen(cwd) + 1 + strlen(file) + 1);
		if (ret)
			sprintf(ret, "%s/%s", cwd, file);
	} else
		ret = strdup(file);
	return ret;
}

void fsck_usage()
{
	MSG(0, "\nUsage: fsck.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -a check/fix potential corruption, reported by f2fs\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -f check/fix entire partition\n");
	MSG(0, "  -p preen mode [default:0 the same as -a [0|1]]\n");
	MSG(0, "  -S sparse_mode\n");
	MSG(0, "  -t show directory tree\n");
	MSG(0, "  -q preserve quota limits\n");
	MSG(0, "  -y fix all the time\n");
	MSG(0, "  --dry-run do not really fix corruptions\n");
	exit(1);
}

void dump_usage()
{
	MSG(0, "\nUsage: dump.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -i inode no (hex)\n");
	MSG(0, "  -n [NAT dump segno from #1~#2 (decimal), for all 0~-1]\n");
	MSG(0, "  -s [SIT dump segno from #1~#2 (decimal), for all 0~-1]\n");
	MSG(0, "  -S sparse_mode\n");
	MSG(0, "  -a [SSA dump segno from #1~#2 (decimal), for all 0~-1]\n");
	MSG(0, "  -b blk_addr (in 4KB)\n");

	exit(1);
}

void defrag_usage()
{
	MSG(0, "\nUsage: defrag.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -s start block address [default: main_blkaddr]\n");
	MSG(0, "  -S sparse_mode\n");
	MSG(0, "  -l length [default:512 (2MB)]\n");
	MSG(0, "  -t target block address [default: main_blkaddr + 2MB]\n");
	MSG(0, "  -i set direction as shrink [default: expand]\n");
	exit(1);
}

void resize_usage()
{
	MSG(0, "\nUsage: resize.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -t target sectors [default: device size]\n");
	exit(1);
}

void sload_usage()
{
	MSG(0, "\nUsage: sload.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -C fs_config\n");
	MSG(0, "  -f source directory [path of the source directory]\n");
	MSG(0, "  -p product out directory\n");
	MSG(0, "  -s file_contexts\n");
	MSG(0, "  -S sparse_mode\n");
	MSG(0, "  -t mount point [prefix of target fs path, default:/]\n");
	MSG(0, "  -T timestamp\n");
	MSG(0, "  -d debug level [default:0]\n");
	exit(1);
}

static int is_digits(char *optarg)
{
	unsigned int i;

	for (i = 0; i < strlen(optarg); i++)
		if (!isdigit(optarg[i]))
			break;
	return i == strlen(optarg);
}

static void error_out(char *prog)
{
	if (!strcmp("fsck.f2fs", prog))
		fsck_usage();
	else if (!strcmp("dump.f2fs", prog))
		dump_usage();
	else if (!strcmp("defrag.f2fs", prog))
		defrag_usage();
	else if (!strcmp("resize.f2fs", prog))
		resize_usage();
	else if (!strcmp("sload.f2fs", prog))
		sload_usage();
	else
		MSG(0, "\nWrong program.\n");
}

void f2fs_parse_options(int argc, char *argv[])
{
	int option = 0;
	char *prog = basename(argv[0]);
	int err = NOERROR;
#ifdef WITH_ANDROID
	int i;

	/* Allow prog names (e.g, sload_f2fs, fsck_f2fs, etc) */
	for (i = 0; i < strlen(prog); i++) {
		if (prog[i] == '_')
			prog[i] = '.';
	}
#endif
	if (argc < 2) {
		MSG(0, "\tError: Device not specified\n");
		error_out(prog);
	}

	if (!strcmp("fsck.f2fs", prog)) {
		const char *option_string = ":ad:fp:q:Sty";
		int opt = 0;
		struct option long_opt[] = {
			{"dry-run", no_argument, 0, 1},
			{0, 0, 0, 0}
		};

		c.func = FSCK;
		while ((option = getopt_long(argc, argv, option_string,
						long_opt, &opt)) != EOF) {
			switch (option) {
			case 1:
				c.dry_run = 1;
				MSG(0, "Info: Dry run\n");
				break;
			case 'a':
				c.auto_fix = 1;
				MSG(0, "Info: Fix the reported corruption.\n");
				break;
			case 'p':
				/* preen mode has different levels:
				 *  0: default level, the same as -a
				 *  1: check meta
				 */
				if (optarg[0] == '-' || !is_digits(optarg) ||
							optind == argc) {
					MSG(0, "Info: Use default preen mode\n");
					c.preen_mode = PREEN_MODE_0;
					c.auto_fix = 1;
					optind--;
					break;
				}
				c.preen_mode = atoi(optarg);
				if (c.preen_mode < 0)
					c.preen_mode = PREEN_MODE_0;
				else if (c.preen_mode >= PREEN_MODE_MAX)
					c.preen_mode = PREEN_MODE_MAX - 1;
				if (c.preen_mode == PREEN_MODE_0)
					c.auto_fix = 1;
				MSG(0, "Info: Fix the reported corruption in "
					"preen mode %d\n", c.preen_mode);
				break;
			case 'd':
				if (optarg[0] == '-') {
					err = ENEED_ARG;
					break;
				} else if (!is_digits(optarg)) {
					err = EWRONG_OPT;
					break;
				}
				c.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n", c.dbg_lv);
				break;
			case 'f':
			case 'y':
				c.fix_on = 1;
				MSG(0, "Info: Force to fix corruption\n");
				break;
			case 'q':
				c.preserve_limits = atoi(optarg);
				MSG(0, "Info: Preserve quota limits = %d\n",
					c.preserve_limits);
				break;
			case 'S':
				c.sparse_mode = 1;
				break;
			case 't':
				c.show_dentry = 1;
				break;
			case ':':
				if (optopt == 'p') {
					MSG(0, "Info: Use default preen mode\n");
					c.preen_mode = PREEN_MODE_0;
					c.auto_fix = 1;
				} else {
					option = optopt;
					err = ENEED_ARG;
					break;
				}
				break;
			case '?':
				option = optopt;
			default:
				err = EUNKNOWN_OPT;
				break;
			}
			if (err != NOERROR)
				break;
		}
	} else if (!strcmp("dump.f2fs", prog)) {
		const char *option_string = "d:i:n:s:Sa:b:f";
		static struct dump_option dump_opt = {
			.nid = 0,	/* default root ino */
			.start_nat = -1,
			.end_nat = -1,
			.start_sit = -1,
			.end_sit = -1,
			.start_ssa = -1,
			.end_ssa = -1,
			.blk_addr = -1,
            .fuzz = 0
		};

		c.func = DUMP;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			int ret = 0;

			switch (option) {
			case 'd':
				if (!is_digits(optarg)) {
					err = EWRONG_OPT;
					break;
				}
				c.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
							c.dbg_lv);
				break;
			case 'i':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%d",
							&dump_opt.nid);
				else
					ret = sscanf(optarg, "%x",
							&dump_opt.nid);
				break;
			case 'n':
				ret = sscanf(optarg, "%d~%d",
							&dump_opt.start_nat,
							&dump_opt.end_nat);
				break;
			case 's':
				ret = sscanf(optarg, "%d~%d",
							&dump_opt.start_sit,
							&dump_opt.end_sit);
				break;
			case 'S':
				c.sparse_mode = 1;
				break;
			case 'a':
				ret = sscanf(optarg, "%d~%d",
							&dump_opt.start_ssa,
							&dump_opt.end_ssa);
				break;
			case 'b':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%d",
							&dump_opt.blk_addr);
				else
					ret = sscanf(optarg, "%x",
							&dump_opt.blk_addr);
				break;
            case 'f':
                dump_opt.fuzz = 1;
                break;
			default:
				err = EUNKNOWN_OPT;
				break;
			}
			ASSERT(ret >= 0);
			if (err != NOERROR)
				break;
		}

		c.private = &dump_opt;
	} else if (!strcmp("defrag.f2fs", prog)) {
		const char *option_string = "d:s:Sl:t:i";

		c.func = DEFRAG;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			int ret = 0;

			switch (option) {
			case 'd':
				if (!is_digits(optarg)) {
					err = EWRONG_OPT;
					break;
				}
				c.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
							c.dbg_lv);
				break;
			case 's':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%"PRIu64"",
							&c.defrag_start);
				else
					ret = sscanf(optarg, "%"PRIx64"",
							&c.defrag_start);
				break;
			case 'S':
				c.sparse_mode = 1;
				break;
			case 'l':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%"PRIu64"",
							&c.defrag_len);
				else
					ret = sscanf(optarg, "%"PRIx64"",
							&c.defrag_len);
				break;
			case 't':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%"PRIu64"",
							&c.defrag_target);
				else
					ret = sscanf(optarg, "%"PRIx64"",
							&c.defrag_target);
				break;
			case 'i':
				c.defrag_shrink = 1;
				break;
			default:
				err = EUNKNOWN_OPT;
				break;
			}
			ASSERT(ret >= 0);
			if (err != NOERROR)
				break;
		}
	} else if (!strcmp("resize.f2fs", prog)) {
		const char *option_string = "d:t:";

		c.func = RESIZE;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			int ret = 0;

			switch (option) {
			case 'd':
				if (!is_digits(optarg)) {
					err = EWRONG_OPT;
					break;
				}
				c.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
							c.dbg_lv);
				break;
			case 't':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%"PRIu64"",
							&c.target_sectors);
				else
					ret = sscanf(optarg, "%"PRIx64"",
							&c.target_sectors);
				break;
			default:
				err = EUNKNOWN_OPT;
				break;
			}
			ASSERT(ret >= 0);
			if (err != NOERROR)
				break;
		}
	} else if (!strcmp("sload.f2fs", prog)) {
		const char *option_string = "C:d:f:p:s:St:T:";
#ifdef HAVE_LIBSELINUX
		int max_nr_opt = (int)sizeof(c.seopt_file) /
			sizeof(c.seopt_file[0]);
		char *token;
#endif
		char *p;

		c.func = SLOAD;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			switch (option) {
			case 'C':
				c.fs_config_file = absolute_path(optarg);
				break;
			case 'd':
				if (!is_digits(optarg)) {
					err = EWRONG_OPT;
					break;
				}
				c.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
						c.dbg_lv);
				break;
			case 'f':
				c.from_dir = absolute_path(optarg);
				break;
			case 'p':
				c.target_out_dir = absolute_path(optarg);
				break;
			case 's':
#ifdef HAVE_LIBSELINUX
				token = strtok(optarg, ",");
				while (token) {
					if (c.nr_opt == max_nr_opt) {
						MSG(0, "\tError: Expected at most %d selinux opts\n",
										max_nr_opt);
						error_out(prog);
					}
					c.seopt_file[c.nr_opt].type =
								SELABEL_OPT_PATH;
					c.seopt_file[c.nr_opt].value =
								absolute_path(token);
					c.nr_opt++;
					token = strtok(NULL, ",");
				}
#else
				MSG(0, "Info: Not support selinux opts\n");
#endif
				break;
			case 'S':
				c.sparse_mode = 1;
				break;
			case 't':
				c.mount_point = (char *)optarg;
				break;
			case 'T':
				c.fixed_time = strtoul(optarg, &p, 0);
				break;
			default:
				err = EUNKNOWN_OPT;
				break;
			}
			if (err != NOERROR)
				break;
		}
	}

	if (optind >= argc) {
		MSG(0, "\tError: Device not specified\n");
		error_out(prog);
	}

	c.devices[0].path = strdup(argv[optind]);
	if (argc > (optind + 1)) {
		c.dbg_lv = 0;
		err = EUNKNOWN_ARG;
	}
	if (err == NOERROR)
		return;

	/* print out error */
	switch (err) {
	case EWRONG_OPT:
		MSG(0, "\tError: Wrong option -%c %s\n", option, optarg);
		break;
	case ENEED_ARG:
		MSG(0, "\tError: Need argument for -%c\n", option);
		break;
	case EUNKNOWN_OPT:
		MSG(0, "\tError: Unknown option %c\n", option);
		break;
	case EUNKNOWN_ARG:
		MSG(0, "\tError: Unknown argument %s\n", argv[optind]);
		break;
	}
	error_out(prog);
}

static void do_fsck(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	u32 flag = le32_to_cpu(ckpt->ckpt_flags);
	u32 blk_cnt;
	errcode_t ret;

	fsck_init(sbi);

	print_cp_state(flag);

	if (!c.fix_on && !c.bug_on) {
		switch (c.preen_mode) {
		case PREEN_MODE_1:
			if (fsck_chk_meta(sbi)) {
				MSG(0, "[FSCK] F2FS metadata   [Fail]");
				MSG(0, "\tError: meta does not match, "
					"force check all\n");
			} else {
				MSG(0, "[FSCK] F2FS metadata   [Ok..]");
				fsck_free(sbi);
				return;
			}

			if (!c.ro)
				c.fix_on = 1;
			break;
		}
	} else if (c.preen_mode) {
		/*
		 * we can hit this in 3 situations:
		 *  1. fsck -f, fix_on has already been set to 1 when
		 *     parsing options;
		 *  2. fsck -a && CP_FSCK_FLAG is set, fix_on has already
		 *     been set to 1 when checking CP_FSCK_FLAG;
		 *  3. fsck -p 1 && error is detected, then bug_on is set,
		 *     we set fix_on = 1 here, so that fsck can fix errors
		 *     automatically
		*/
		c.fix_on = 1;
	}

	fsck_chk_quota_node(sbi);

	/* Traverse all block recursively from root inode */
	blk_cnt = 1;

	if (c.feature & cpu_to_le32(F2FS_FEATURE_QUOTA_INO)) {
		ret = quota_init_context(sbi);
		if (ret) {
			ASSERT_MSG("quota_init_context failure: %d", ret);
			return;
		}
	}
	fsck_chk_orphan_node(sbi);
	fsck_chk_node_blk(sbi, NULL, sbi->root_ino_num,
			F2FS_FT_DIR, TYPE_INODE, &blk_cnt, NULL);
	fsck_chk_quota_files(sbi);

	fsck_verify(sbi);
	fsck_free(sbi);
}

static void do_dump(struct f2fs_sb_info *sbi)
{
	struct dump_option *opt = (struct dump_option *)c.private;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	u32 flag = le32_to_cpu(ckpt->ckpt_flags);

	if (opt->end_nat == -1)
		opt->end_nat = NM_I(sbi)->max_nid;
	if (opt->end_sit == -1)
		opt->end_sit = SM_I(sbi)->main_segments;
	if (opt->end_ssa == -1)
		opt->end_ssa = SM_I(sbi)->main_segments;
	if (opt->start_nat != -1)
		nat_dump(sbi);
	if (opt->start_sit != -1)
		sit_dump(sbi, opt->start_sit, opt->end_sit);
	if (opt->start_ssa != -1)
		ssa_dump(sbi, opt->start_ssa, opt->end_ssa);
	if (opt->blk_addr != -1)
		dump_info_from_blkaddr(sbi, opt->blk_addr);
	if (opt->nid)
		dump_node(sbi, opt->nid, 0);
    if (opt->fuzz)
        dump_info_for_fuzz(sbi);

	print_cp_state(flag);

}

static int do_defrag(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);

	if (c.defrag_start > get_sb(block_count))
		goto out_range;
	if (c.defrag_start < SM_I(sbi)->main_blkaddr)
		c.defrag_start = SM_I(sbi)->main_blkaddr;

	if (c.defrag_len == 0)
		c.defrag_len = sbi->blocks_per_seg;

	if (c.defrag_start + c.defrag_len > get_sb(block_count))
		c.defrag_len = get_sb(block_count) - c.defrag_start;

	if (c.defrag_target == 0) {
		c.defrag_target = c.defrag_start - 1;
		if (!c.defrag_shrink)
			c.defrag_target += c.defrag_len + 1;
	}

	if (c.defrag_target < SM_I(sbi)->main_blkaddr ||
			c.defrag_target > get_sb(block_count))
		goto out_range;
	if (c.defrag_target >= c.defrag_start &&
		c.defrag_target < c.defrag_start + c.defrag_len)
		goto out_range;

	if (c.defrag_start > c.defrag_target)
		MSG(0, "Info: Move 0x%"PRIx64" <- [0x%"PRIx64"-0x%"PRIx64"]\n",
				c.defrag_target,
				c.defrag_start,
				c.defrag_start + c.defrag_len - 1);
	else
		MSG(0, "Info: Move [0x%"PRIx64"-0x%"PRIx64"] -> 0x%"PRIx64"\n",
				c.defrag_start,
				c.defrag_start + c.defrag_len - 1,
				c.defrag_target);

	return f2fs_defragment(sbi, c.defrag_start, c.defrag_len,
			c.defrag_target, c.defrag_shrink);
out_range:
	ASSERT_MSG("Out-of-range [0x%"PRIx64" ~ 0x%"PRIx64"] to 0x%"PRIx64"",
				c.defrag_start,
				c.defrag_start + c.defrag_len - 1,
				c.defrag_target);
	return -1;
}

static int do_resize(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);

	if (!c.target_sectors)
		c.target_sectors = c.total_sectors;

	if (c.target_sectors > c.total_sectors) {
		ASSERT_MSG("Out-of-range Target=0x%"PRIx64" / 0x%"PRIx64"",
				c.target_sectors, c.total_sectors);
		return -1;
	}

	/* may different sector size */
	if ((c.target_sectors * c.sector_size >>
			get_sb(log_blocksize)) <= get_sb(block_count)) {
		ASSERT_MSG("Nothing to resize, now only support resize to expand\n");
		return -1;
	}
	return f2fs_resize(sbi);
}

static int do_sload(struct f2fs_sb_info *sbi)
{
	if (!c.from_dir) {
		MSG(0, "Info: No source directory, but it's okay.\n");
		return 0;
	}
	if (!c.mount_point)
		c.mount_point = "/";

	return f2fs_sload(sbi);
}

int main(int argc, char **argv)
{
	struct f2fs_sb_info *sbi;
	int ret = 0;

	f2fs_init_configuration();

	f2fs_parse_options(argc, argv);

	if (f2fs_devs_are_umounted() < 0) {
		if (errno == EBUSY)
			return -1;
		if (!c.ro || c.func == DEFRAG) {
			MSG(0, "\tError: Not available on mounted device!\n");
			return -1;
		}

		/* allow ro-mounted partition */
		MSG(0, "Info: Check FS only due to RO\n");
		c.fix_on = 0;
		c.auto_fix = 0;
	}

	/* Get device */
	if (f2fs_get_device_info() < 0)
		return -1;

fsck_again:
	memset(&gfsck, 0, sizeof(gfsck));
	gfsck.sbi.fsck = &gfsck;
	sbi = &gfsck.sbi;

	ret = f2fs_do_mount(sbi);
	if (ret != 0) {
		if (ret == 1) {
			MSG(0, "Info: No error was reported\n");
			ret = 0;
		}
		goto out_err;
	}

	switch (c.func) {
	case FSCK:
		do_fsck(sbi);
		break;
#ifdef WITH_DUMP
	case DUMP:
		do_dump(sbi);
		break;
#endif
#ifdef WITH_DEFRAG
	case DEFRAG:
		ret = do_defrag(sbi);
		if (ret)
			goto out_err;
		break;
#endif
#ifdef WITH_RESIZE
	case RESIZE:
		if (do_resize(sbi))
			goto out_err;
		break;
#endif
#ifdef WITH_SLOAD
	case SLOAD:
		if (do_sload(sbi))
			goto out_err;

		f2fs_do_umount(sbi);

		/* fsck to fix missing quota */
		c.func = FSCK;
		c.fix_on = 1;
		goto fsck_again;
#endif
	default:
		ERR_MSG("Wrong program name\n");
		ASSERT(0);
	}

	f2fs_do_umount(sbi);

	if (c.func == FSCK && c.bug_on) {
		if (!c.ro && c.fix_on == 0 && c.auto_fix == 0) {
			char ans[255] = {0};
retry:
			printf("Do you want to fix this partition? [Y/N] ");
			ret = scanf("%s", ans);
			ASSERT(ret >= 0);
			if (!strcasecmp(ans, "y"))
				c.fix_on = 1;
			else if (!strcasecmp(ans, "n"))
				c.fix_on = 0;
			else
				goto retry;

			if (c.fix_on)
				goto fsck_again;
		}
	}
	ret = f2fs_finalize_device();
	if (ret < 0)
		return ret;

	printf("\nDone.\n");
	return 0;

out_err:
	if (sbi->ckpt)
		free(sbi->ckpt);
	if (sbi->raw_super)
		free(sbi->raw_super);
	return ret;
}
