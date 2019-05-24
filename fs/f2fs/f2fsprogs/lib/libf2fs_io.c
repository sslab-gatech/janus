/**
 * libf2fs.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif
#include <time.h>
#ifndef ANDROID_WINDOWS_HOST
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
#endif

#include <f2fs_fs.h>

struct f2fs_configuration c;

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
struct sparse_file *f2fs_sparse_file;
static char **blocks;
u_int64_t blocks_count;
#endif

static int __get_device_fd(__u64 *offset)
{
	__u64 blk_addr = *offset >> F2FS_BLKSIZE_BITS;
	int i;

	for (i = 0; i < c.ndevs; i++) {
		if (c.devices[i].start_blkaddr <= blk_addr &&
				c.devices[i].end_blkaddr >= blk_addr) {
			*offset -=
				c.devices[i].start_blkaddr << F2FS_BLKSIZE_BITS;
			return c.devices[i].fd;
		}
	}
	return -1;
}

#ifndef HAVE_LSEEK64
typedef off_t	off64_t;

static inline off64_t lseek64(int fd, __u64 offset, int set)
{
	return lseek(fd, offset, set);
}
#endif

/*
 * IO interfaces
 */
int dev_read_version(void *buf, __u64 offset, size_t len)
{
	if (c.sparse_mode)
		return 0;
	if (lseek64(c.kd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(c.kd, buf, len) < 0)
		return -1;
	return 0;
}

#ifdef WITH_ANDROID
static int sparse_read_blk(__u64 block, int count, void *buf)
{
	int i;
	char *out = buf;
	__u64 cur_block;

	for (i = 0; i < count; ++i) {
		cur_block = block + i;
		if (blocks[cur_block])
			memcpy(out + (i * F2FS_BLKSIZE),
					blocks[cur_block], F2FS_BLKSIZE);
		else if (blocks)
			memset(out + (i * F2FS_BLKSIZE), 0, F2FS_BLKSIZE);
	}
	return 0;
}

static int sparse_write_blk(__u64 block, int count, const void *buf)
{
	int i;
	__u64 cur_block;
	const char *in = buf;

	for (i = 0; i < count; ++i) {
		cur_block = block + i;
		if (!blocks[cur_block]) {
			blocks[cur_block] = calloc(1, F2FS_BLKSIZE);
			if (!blocks[cur_block])
				return -ENOMEM;
		}
		memcpy(blocks[cur_block], in + (i * F2FS_BLKSIZE),
				F2FS_BLKSIZE);
	}
	return 0;
}

#ifdef SPARSE_CALLBACK_USES_SIZE_T
static int sparse_import_segment(void *UNUSED(priv), const void *data,
		size_t len, unsigned int block, unsigned int nr_blocks)
#else
static int sparse_import_segment(void *UNUSED(priv), const void *data, int len,
		unsigned int block, unsigned int nr_blocks)
#endif
{
	/* Ignore chunk headers, only write the data */
	if (!nr_blocks || len % F2FS_BLKSIZE)
		return 0;

	return sparse_write_blk(block, nr_blocks, data);
}

static int sparse_merge_blocks(uint64_t start, uint64_t num)
{
	char *buf;
	uint64_t i;

	buf = calloc(num, F2FS_BLKSIZE);
	if (!buf) {
		fprintf(stderr, "failed to alloc %llu\n",
			(unsigned long long)num * F2FS_BLKSIZE);
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		memcpy(buf + i * F2FS_BLKSIZE, blocks[start + i], F2FS_BLKSIZE);
		free(blocks[start + i]);
		blocks[start + i] = NULL;
	}

	/* free_sparse_blocks will release this buf. */
	blocks[start] = buf;

	return sparse_file_add_data(f2fs_sparse_file, blocks[start],
					F2FS_BLKSIZE * num, start);
}
#else
static int sparse_read_blk(__u64 block, int count, void *buf) { return 0; }
static int sparse_write_blk(__u64 block, int count, const void *buf) { return 0; }
#endif

int dev_read(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return sparse_read_blk(offset / F2FS_BLKSIZE,
					len / F2FS_BLKSIZE, buf);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(fd, buf, len) < 0)
		return -1;
	return 0;
}

#ifdef POSIX_FADV_WILLNEED
int dev_readahead(__u64 offset, size_t len)
#else
int dev_readahead(__u64 offset, size_t UNUSED(len))
#endif
{
	int fd = __get_device_fd(&offset);

	if (fd < 0)
		return fd;
#ifdef POSIX_FADV_WILLNEED
	return posix_fadvise(fd, offset, len, POSIX_FADV_WILLNEED);
#else
	return 0;
#endif
}

int dev_write(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.dry_run)
		return 0;

	if (c.sparse_mode)
		return sparse_write_blk(offset / F2FS_BLKSIZE,
					len / F2FS_BLKSIZE, buf);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_write_block(void *buf, __u64 blk_addr)
{
	return dev_write(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_write_dump(void *buf, __u64 offset, size_t len)
{
	if (lseek64(c.dump_fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(c.dump_fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_fill(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return 0;

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	/* Only allow fill to zero */
	if (*((__u8*)buf))
		return -1;
	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_fill_block(void *buf, __u64 blk_addr)
{
	return dev_fill(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_read_block(void *buf, __u64 blk_addr)
{
	return dev_read(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_reada_block(__u64 blk_addr)
{
	return dev_readahead(blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int f2fs_fsync_device(void)
{
#ifndef ANDROID_WINDOWS_HOST
	int i;

	for (i = 0; i < c.ndevs; i++) {
		if (fsync(c.devices[i].fd) < 0) {
			MSG(0, "\tError: Could not conduct fsync!!!\n");
			return -1;
		}
	}
#endif
	return 0;
}

int f2fs_init_sparse_file(void)
{
#ifdef WITH_ANDROID
	if (c.func == MKFS) {
		f2fs_sparse_file = sparse_file_new(F2FS_BLKSIZE, c.device_size);
	} else {
		f2fs_sparse_file = sparse_file_import(c.devices[0].fd,
							true, false);
		if (!f2fs_sparse_file)
			return -1;

		c.device_size = sparse_file_len(f2fs_sparse_file, 0, 0);
		c.device_size &= (~((u_int64_t)(F2FS_BLKSIZE - 1)));
	}

	if (sparse_file_block_size(f2fs_sparse_file) != F2FS_BLKSIZE) {
		MSG(0, "\tError: Corrupted sparse file\n");
		return -1;
	}
	blocks_count = c.device_size / F2FS_BLKSIZE;
	blocks = calloc(blocks_count, sizeof(char *));

	return sparse_file_foreach_chunk(f2fs_sparse_file, true, false,
				sparse_import_segment, NULL);
#else
	MSG(0, "\tError: Sparse mode is only supported for android\n");
	return -1;
#endif
}

int f2fs_finalize_device(void)
{
	int i;
	int ret = 0;

#ifdef WITH_ANDROID
	if (c.sparse_mode) {
		int64_t chunk_start = (blocks[0] == NULL) ? -1 : 0;
		uint64_t j;

		if (c.func != MKFS) {
			sparse_file_destroy(f2fs_sparse_file);
			ret = ftruncate(c.devices[0].fd, 0);
			ASSERT(!ret);
			lseek(c.devices[0].fd, 0, SEEK_SET);
			f2fs_sparse_file = sparse_file_new(F2FS_BLKSIZE,
							c.device_size);
		}

		for (j = 0; j < blocks_count; ++j) {
			if (!blocks[j] && chunk_start != -1) {
				ret = sparse_merge_blocks(chunk_start,
							j - chunk_start);
				chunk_start = -1;
			} else if (blocks[j] && chunk_start == -1) {
				chunk_start = j;
			}
			ASSERT(!ret);
		}
		if (chunk_start != -1) {
			ret = sparse_merge_blocks(chunk_start,
						blocks_count - chunk_start);
			ASSERT(!ret);
		}

		sparse_file_write(f2fs_sparse_file, c.devices[0].fd,
				/*gzip*/0, /*sparse*/1, /*crc*/0);

		sparse_file_destroy(f2fs_sparse_file);
		for (j = 0; j < blocks_count; j++)
			free(blocks[j]);
		free(blocks);
		blocks = NULL;
		f2fs_sparse_file = NULL;
	}
#endif
	/*
	 * We should call fsync() to flush out all the dirty pages
	 * in the block device page cache.
	 */
	for (i = 0; i < c.ndevs; i++) {
#ifndef ANDROID_WINDOWS_HOST
		ret = fsync(c.devices[i].fd);
		if (ret < 0) {
			MSG(0, "\tError: Could not conduct fsync!!!\n");
			break;
		}
#endif
		ret = close(c.devices[i].fd);
		if (ret < 0) {
			MSG(0, "\tError: Failed to close device file!!!\n");
			break;
		}
	}
	close(c.kd);

	return ret;
}
