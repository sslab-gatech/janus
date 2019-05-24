/**
 * libf2fs.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include <f2fs_fs.h>
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
#include <sys/stat.h>
#ifndef ANDROID_WINDOWS_HOST
#include <sys/mount.h>
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifndef WITH_ANDROID
#ifdef HAVE_SCSI_SG_H
#include <scsi/sg.h>
#endif
#endif
#ifdef HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
#endif
#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif

#ifndef WITH_ANDROID
/* SCSI command for standard inquiry*/
#define MODELINQUIRY	0x12,0x00,0x00,0x00,0x4A,0x00
#endif

#ifndef ANDROID_WINDOWS_HOST /* O_BINARY is windows-specific flag */
#define O_BINARY 0
#else
/* On Windows, wchar_t is 8 bit sized and it causes compilation errors. */
#define wchar_t	int
#endif

/*
 * UTF conversion codes are Copied from exfat tools.
 */
static const char *utf8_to_wchar(const char *input, wchar_t *wc,
		size_t insize)
{
	if ((input[0] & 0x80) == 0 && insize >= 1) {
		*wc = (wchar_t) input[0];
		return input + 1;
	}
	if ((input[0] & 0xe0) == 0xc0 && insize >= 2) {
		*wc = (((wchar_t) input[0] & 0x1f) << 6) |
		       ((wchar_t) input[1] & 0x3f);
		return input + 2;
	}
	if ((input[0] & 0xf0) == 0xe0 && insize >= 3) {
		*wc = (((wchar_t) input[0] & 0x0f) << 12) |
		      (((wchar_t) input[1] & 0x3f) << 6) |
		       ((wchar_t) input[2] & 0x3f);
		return input + 3;
	}
	if ((input[0] & 0xf8) == 0xf0 && insize >= 4) {
		*wc = (((wchar_t) input[0] & 0x07) << 18) |
		      (((wchar_t) input[1] & 0x3f) << 12) |
		      (((wchar_t) input[2] & 0x3f) << 6) |
		       ((wchar_t) input[3] & 0x3f);
		return input + 4;
	}
	if ((input[0] & 0xfc) == 0xf8 && insize >= 5) {
		*wc = (((wchar_t) input[0] & 0x03) << 24) |
		      (((wchar_t) input[1] & 0x3f) << 18) |
		      (((wchar_t) input[2] & 0x3f) << 12) |
		      (((wchar_t) input[3] & 0x3f) << 6) |
		       ((wchar_t) input[4] & 0x3f);
		return input + 5;
	}
	if ((input[0] & 0xfe) == 0xfc && insize >= 6) {
		*wc = (((wchar_t) input[0] & 0x01) << 30) |
		      (((wchar_t) input[1] & 0x3f) << 24) |
		      (((wchar_t) input[2] & 0x3f) << 18) |
		      (((wchar_t) input[3] & 0x3f) << 12) |
		      (((wchar_t) input[4] & 0x3f) << 6) |
		       ((wchar_t) input[5] & 0x3f);
		return input + 6;
	}
	return NULL;
}

static u_int16_t *wchar_to_utf16(u_int16_t *output, wchar_t wc, size_t outsize)
{
	if (wc <= 0xffff) {
		if (outsize == 0)
			return NULL;
		output[0] = cpu_to_le16(wc);
		return output + 1;
	}
	if (outsize < 2)
		return NULL;
	wc -= 0x10000;
	output[0] = cpu_to_le16(0xd800 | ((wc >> 10) & 0x3ff));
	output[1] = cpu_to_le16(0xdc00 | (wc & 0x3ff));
	return output + 2;
}

int utf8_to_utf16(u_int16_t *output, const char *input, size_t outsize,
		size_t insize)
{
	const char *inp = input;
	u_int16_t *outp = output;
	wchar_t wc;

	while ((size_t)(inp - input) < insize && *inp) {
		inp = utf8_to_wchar(inp, &wc, insize - (inp - input));
		if (inp == NULL) {
			DBG(0, "illegal UTF-8 sequence\n");
			return -EILSEQ;
		}
		outp = wchar_to_utf16(outp, wc, outsize - (outp - output));
		if (outp == NULL) {
			DBG(0, "name is too long\n");
			return -ENAMETOOLONG;
		}
	}
	*outp = cpu_to_le16(0);
	return 0;
}

static const u_int16_t *utf16_to_wchar(const u_int16_t *input, wchar_t *wc,
		size_t insize)
{
	if ((le16_to_cpu(input[0]) & 0xfc00) == 0xd800) {
		if (insize < 2 || (le16_to_cpu(input[1]) & 0xfc00) != 0xdc00)
			return NULL;
		*wc = ((wchar_t) (le16_to_cpu(input[0]) & 0x3ff) << 10);
		*wc |= (le16_to_cpu(input[1]) & 0x3ff);
		*wc += 0x10000;
		return input + 2;
	} else {
		*wc = le16_to_cpu(*input);
		return input + 1;
	}
}

static char *wchar_to_utf8(char *output, wchar_t wc, size_t outsize)
{
	if (wc <= 0x7f) {
		if (outsize < 1)
			return NULL;
		*output++ = (char) wc;
	} else if (wc <= 0x7ff) {
		if (outsize < 2)
			return NULL;
		*output++ = 0xc0 | (wc >> 6);
		*output++ = 0x80 | (wc & 0x3f);
	} else if (wc <= 0xffff) {
		if (outsize < 3)
			return NULL;
		*output++ = 0xe0 | (wc >> 12);
		*output++ = 0x80 | ((wc >> 6) & 0x3f);
		*output++ = 0x80 | (wc & 0x3f);
	} else if (wc <= 0x1fffff) {
		if (outsize < 4)
			return NULL;
		*output++ = 0xf0 | (wc >> 18);
		*output++ = 0x80 | ((wc >> 12) & 0x3f);
		*output++ = 0x80 | ((wc >> 6) & 0x3f);
		*output++ = 0x80 | (wc & 0x3f);
	} else if (wc <= 0x3ffffff) {
		if (outsize < 5)
			return NULL;
		*output++ = 0xf8 | (wc >> 24);
		*output++ = 0x80 | ((wc >> 18) & 0x3f);
		*output++ = 0x80 | ((wc >> 12) & 0x3f);
		*output++ = 0x80 | ((wc >> 6) & 0x3f);
		*output++ = 0x80 | (wc & 0x3f);
	} else if (wc <= 0x7fffffff) {
		if (outsize < 6)
			return NULL;
		*output++ = 0xfc | (wc >> 30);
		*output++ = 0x80 | ((wc >> 24) & 0x3f);
		*output++ = 0x80 | ((wc >> 18) & 0x3f);
		*output++ = 0x80 | ((wc >> 12) & 0x3f);
		*output++ = 0x80 | ((wc >> 6) & 0x3f);
		*output++ = 0x80 | (wc & 0x3f);
	} else
		return NULL;

	return output;
}

int utf16_to_utf8(char *output, const u_int16_t *input, size_t outsize,
		size_t insize)
{
	const u_int16_t *inp = input;
	char *outp = output;
	wchar_t wc;

	while ((size_t)(inp - input) < insize && le16_to_cpu(*inp)) {
		inp = utf16_to_wchar(inp, &wc, insize - (inp - input));
		if (inp == NULL) {
			DBG(0, "illegal UTF-16 sequence\n");
			return -EILSEQ;
		}
		outp = wchar_to_utf8(outp, wc, outsize - (outp - output));
		if (outp == NULL) {
			DBG(0, "name is too long\n");
			return -ENAMETOOLONG;
		}
	}
	*outp = '\0';
	return 0;
}

int log_base_2(u_int32_t num)
{
	int ret = 0;
	if (num <= 0 || (num & (num - 1)) != 0)
		return -1;

	while (num >>= 1)
		ret++;
	return ret;
}

/*
 * f2fs bit operations
 */
static const int bits_in_byte[256] = {
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

int get_bits_in_byte(unsigned char n)
{
	return bits_in_byte[n];
}

int test_and_set_bit_le(u32 nr, u8 *addr)
{
	int mask, retval;

	addr += nr >> 3;
	mask = 1 << ((nr & 0x07));
	retval = mask & *addr;
	*addr |= mask;
	return retval;
}

int test_and_clear_bit_le(u32 nr, u8 *addr)
{
	int mask, retval;

	addr += nr >> 3;
	mask = 1 << ((nr & 0x07));
	retval = mask & *addr;
	*addr &= ~mask;
	return retval;
}

int test_bit_le(u32 nr, const u8 *addr)
{
	return ((1 << (nr & 7)) & (addr[nr >> 3]));
}

int f2fs_test_bit(unsigned int nr, const char *p)
{
	int mask;
	char *addr = (char *)p;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	return (mask & *addr) != 0;
}

int f2fs_set_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr |= mask;
	return ret;
}

int f2fs_clear_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr &= ~mask;
	return ret;
}

static inline u64 __ffs(u8 word)
{
	int num = 0;

	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

/* Copied from linux/lib/find_bit.c */
#define BITMAP_FIRST_BYTE_MASK(start) (0xff << ((start) & (BITS_PER_BYTE - 1)))

static u64 _find_next_bit_le(const u8 *addr, u64 nbits, u64 start, char invert)
{
	u8 tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_BYTE] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_BYTE_MASK(start);
	start = round_down(start, BITS_PER_BYTE);

	while (!tmp) {
		start += BITS_PER_BYTE;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_BYTE] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

u64 find_next_bit_le(const u8 *addr, u64 size, u64 offset)
{
	return _find_next_bit_le(addr, size, offset, 0);
}


u64 find_next_zero_bit_le(const u8 *addr, u64 size, u64 offset)
{
	return _find_next_bit_le(addr, size, offset, 0xff);
}

/*
 * Hashing code adapted from ext3
 */
#define DELTA 0x9E3779B9

static void TEA_transform(unsigned int buf[4], unsigned int const in[])
{
	__u32 sum = 0;
	__u32 b0 = buf[0], b1 = buf[1];
	__u32 a = in[0], b = in[1], c = in[2], d = in[3];
	int     n = 16;

	do {
		sum += DELTA;
		b0 += ((b1 << 4)+a) ^ (b1+sum) ^ ((b1 >> 5)+b);
		b1 += ((b0 << 4)+c) ^ (b0+sum) ^ ((b0 >> 5)+d);
	} while (--n);

	buf[0] += b0;
	buf[1] += b1;

}

static void str2hashbuf(const unsigned char *msg, int len,
					unsigned int *buf, int num)
{
	unsigned pad, val;
	int i;

	pad = (__u32)len | ((__u32)len << 8);
	pad |= pad << 16;

	val = pad;
	if (len > num * 4)
		len = num * 4;
	for (i = 0; i < len; i++) {
		if ((i % 4) == 0)
			val = pad;
		val = msg[i] + (val << 8);
		if ((i % 4) == 3) {
			*buf++ = val;
			val = pad;
			num--;
		}
	}
	if (--num >= 0)
		*buf++ = val;
	while (--num >= 0)
		*buf++ = pad;

}

/**
 * Return hash value of directory entry
 * @param name          dentry name
 * @param len           name lenth
 * @return              return on success hash value, errno on failure
 */
f2fs_hash_t f2fs_dentry_hash(const unsigned char *name, int len)
{
	__u32 hash;
	f2fs_hash_t	f2fs_hash;
	const unsigned char	*p;
	__u32 in[8], buf[4];

	/* special hash codes for special dentries */
	if ((len <= 2) && (name[0] == '.') &&
		(name[1] == '.' || name[1] == '\0'))
		return 0;

	/* Initialize the default seed for the hash checksum functions */
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;

	p = name;
	while (1) {
		str2hashbuf(p, len, in, 4);
		TEA_transform(buf, in);
		p += 16;
		if (len <= 16)
			break;
		len -= 16;
	}
	hash = buf[0];

	f2fs_hash = cpu_to_le32(hash & ~F2FS_HASH_COL_BIT);
	return f2fs_hash;
}

unsigned int addrs_per_inode(struct f2fs_inode *i)
{
	return CUR_ADDRS_PER_INODE(i) - get_inline_xattr_addrs(i);
}

/*
 * CRC32
 */
#define CRCPOLY_LE 0xedb88320

u_int32_t f2fs_cal_crc32(u_int32_t crc, void *buf, int len)
{
	int i;
	unsigned char *p = (unsigned char *)buf;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}

int f2fs_crc_valid(u_int32_t blk_crc, void *buf, int len)
{
	u_int32_t cal_crc = 0;

	cal_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, buf, len);

	if (cal_crc != blk_crc)	{
		DBG(0,"CRC validation failed: cal_crc = %u, "
			"blk_crc = %u buff_size = 0x%x\n",
			cal_crc, blk_crc, len);
		return -1;
	}
	return 0;
}

__u32 f2fs_inode_chksum(struct f2fs_node *node)
{
	struct f2fs_inode *ri = &node->i;
	__le32 ino = node->footer.ino;
	__le32 gen = ri->i_generation;
	__u32 chksum, chksum_seed;
	__u32 dummy_cs = 0;
	unsigned int offset = offsetof(struct f2fs_inode, i_inode_checksum);
	unsigned int cs_size = sizeof(dummy_cs);

	chksum = f2fs_cal_crc32(c.chksum_seed, (__u8 *)&ino,
							sizeof(ino));
	chksum_seed = f2fs_cal_crc32(chksum, (__u8 *)&gen, sizeof(gen));

	chksum = f2fs_cal_crc32(chksum_seed, (__u8 *)ri, offset);
	chksum = f2fs_cal_crc32(chksum, (__u8 *)&dummy_cs, cs_size);
	offset += cs_size;
	chksum = f2fs_cal_crc32(chksum, (__u8 *)ri + offset,
						F2FS_BLKSIZE - offset);
	return chksum;
}

/*
 * try to identify the root device
 */
const char *get_rootdev()
{
#if defined(ANDROID_WINDOWS_HOST) || defined(WITH_ANDROID)
	return NULL;
#else
	struct stat sb;
	int fd, ret;
	char buf[32];
	char *uevent, *ptr;

	static char rootdev[PATH_MAX + 1];

	if (stat("/", &sb) == -1)
		return NULL;

	snprintf(buf, 32, "/sys/dev/block/%u:%u/uevent",
		major(sb.st_dev), minor(sb.st_dev));

	fd = open(buf, O_RDONLY);

	if (fd < 0)
		return NULL;

	ret = lseek(fd, (off_t)0, SEEK_END);
	(void)lseek(fd, (off_t)0, SEEK_SET);

	if (ret == -1) {
		close(fd);
		return NULL;
	}

	uevent = malloc(ret + 1);
	uevent[ret] = '\0';

	ret = read(fd, uevent, ret);
	close(fd);

	ptr = strstr(uevent, "DEVNAME");
	if (!ptr)
		return NULL;

	ret = sscanf(ptr, "DEVNAME=%s\n", buf);
	snprintf(rootdev, PATH_MAX + 1, "/dev/%s", buf);

	return rootdev;
#endif
}

/*
 * device information
 */
void f2fs_init_configuration(void)
{
	int i;

	memset(&c, 0, sizeof(struct f2fs_configuration));
	c.ndevs = 1;
	c.sectors_per_blk = DEFAULT_SECTORS_PER_BLOCK;
	c.blks_per_seg = DEFAULT_BLOCKS_PER_SEGMENT;
	c.rootdev_name = get_rootdev();
	c.wanted_total_sectors = -1;
	c.wanted_sector_size = -1;
#ifndef WITH_ANDROID
	c.preserve_limits = 1;
#endif

	for (i = 0; i < MAX_DEVICES; i++) {
		c.devices[i].fd = -1;
		c.devices[i].sector_size = DEFAULT_SECTOR_SIZE;
		c.devices[i].end_blkaddr = -1;
		c.devices[i].zoned_model = F2FS_ZONED_NONE;
	}

	/* calculated by overprovision ratio */
	c.segs_per_sec = 1;
	c.secs_per_zone = 1;
	c.segs_per_zone = 1;
	c.vol_label = "";
	c.trim = 1;
	c.kd = -1;
	c.fixed_time = -1;
}

#ifdef HAVE_SETMNTENT
static int is_mounted(const char *mpt, const char *device)
{
	FILE *file = NULL;
	struct mntent *mnt = NULL;

	file = setmntent(mpt, "r");
	if (file == NULL)
		return 0;

	while ((mnt = getmntent(file)) != NULL) {
		if (!strcmp(device, mnt->mnt_fsname)) {
#ifdef MNTOPT_RO
			if (hasmntopt(mnt, MNTOPT_RO))
				c.ro = 1;
#endif
			break;
		}
	}
	endmntent(file);
	return mnt ? 1 : 0;
}
#endif

int f2fs_dev_is_umounted(char *path)
{
#ifdef ANDROID_WINDOWS_HOST
	return 0;
#else
	struct stat *st_buf;
	int is_rootdev = 0;
	int ret = 0;

	if (c.rootdev_name && !strcmp(path, c.rootdev_name))
		is_rootdev = 1;

	/*
	 * try with /proc/mounts fist to detect RDONLY.
	 * f2fs_stop_checkpoint makes RO in /proc/mounts while RW in /etc/mtab.
	 */
#ifdef __linux__
	ret = is_mounted("/proc/mounts", path);
	if (ret) {
		MSG(0, "Info: Mounted device!\n");
		return -1;
	}
#endif
#if defined(MOUNTED) || defined(_PATH_MOUNTED)
#ifndef MOUNTED
#define MOUNTED _PATH_MOUNTED
#endif
	ret = is_mounted(MOUNTED, path);
	if (ret) {
		MSG(0, "Info: Mounted device!\n");
		return -1;
	}
#endif
	/*
	 * If we are supposed to operate on the root device, then
	 * also check the mounts for '/dev/root', which sometimes
	 * functions as an alias for the root device.
	 */
	if (is_rootdev) {
#ifdef __linux__
		ret = is_mounted("/proc/mounts", "/dev/root");
		if (ret) {
			MSG(0, "Info: Mounted device!\n");
			return -1;
		}
#endif
	}

	/*
	 * If f2fs is umounted with -l, the process can still use
	 * the file system. In this case, we should not format.
	 */
	st_buf = malloc(sizeof(struct stat));
	if (stat(path, st_buf) == 0 && S_ISBLK(st_buf->st_mode)) {
		int fd = open(path, O_RDONLY | O_EXCL);

		if (fd >= 0) {
			close(fd);
		} else if (errno == EBUSY) {
			MSG(0, "\tError: In use by the system!\n");
			free(st_buf);
			return -1;
		}
	}
	free(st_buf);
	return ret;
#endif
}

int f2fs_devs_are_umounted(void)
{
	int i;

	for (i = 0; i < c.ndevs; i++)
		if (f2fs_dev_is_umounted((char *)c.devices[i].path))
			return -1;
	return 0;
}

void get_kernel_version(__u8 *version)
{
	int i;
	for (i = 0; i < VERSION_LEN; i++) {
		if (version[i] == '\n')
			break;
	}
	memset(version + i, 0, VERSION_LEN + 1 - i);
}

void get_kernel_uname_version(__u8 *version)
{
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname buf;

	memset(version, 0, VERSION_LEN);
	if (uname(&buf))
		return;

	snprintf((char *)version,
		VERSION_LEN, "%s %s", buf.release, buf.version);
#else
	memset(version, 0, VERSION_LEN);
#endif
}

#if defined(__linux__) && defined(_IO) && !defined(BLKGETSIZE)
#define BLKGETSIZE	_IO(0x12,96)
#endif

#if defined(__linux__) && defined(_IOR) && !defined(BLKGETSIZE64)
#define BLKGETSIZE64	_IOR(0x12,114, size_t)
#endif

#if defined(__linux__) && defined(_IO) && !defined(BLKSSZGET)
#define BLKSSZGET	_IO(0x12,104)
#endif

#if defined(__APPLE__)
#include <sys/disk.h>
#define BLKGETSIZE	DKIOCGETBLOCKCOUNT
#define BLKSSZGET	DKIOCGETBLOCKCOUNT
#endif /* APPLE_DARWIN */

#ifndef ANDROID_WINDOWS_HOST
int get_device_info(int i)
{
	int32_t fd = 0;
	uint32_t sector_size;
#ifndef BLKGETSIZE64
	uint32_t total_sectors;
#endif
	struct stat *stat_buf;
#ifdef HDIO_GETGIO
	struct hd_geometry geom;
#endif
#if !defined(WITH_ANDROID) && defined(__linux__)
	sg_io_hdr_t io_hdr;
	unsigned char reply_buffer[96] = {0};
	unsigned char model_inq[6] = {MODELINQUIRY};
#endif
	struct device_info *dev = c.devices + i;

	if (c.sparse_mode) {
		fd = open((char *)dev->path, O_RDWR | O_CREAT | O_BINARY, 0644);
	} else {
		fd = open((char *)dev->path, O_RDWR);
	}
	if (fd < 0) {
		MSG(0, "\tError: Failed to open the device!\n");
		return -1;
	}

	dev->fd = fd;

	if (c.sparse_mode) {
		if (f2fs_init_sparse_file())
			return -1;
	}

	if (c.kd == -1) {
#if !defined(WITH_ANDROID) && defined(__linux__)
		c.kd = open("/proc/version", O_RDONLY);
#endif
		if (c.kd < 0) {
			MSG(0, "\tInfo: No support kernel version!\n");
			c.kd = -2;
		}
	}

	stat_buf = malloc(sizeof(struct stat));
	if (fstat(fd, stat_buf) < 0 ) {
		MSG(0, "\tError: Failed to get the device stat!\n");
		free(stat_buf);
		return -1;
	}

	if (c.sparse_mode) {
		dev->total_sectors = c.device_size / dev->sector_size;
	} else if (S_ISREG(stat_buf->st_mode)) {
		dev->total_sectors = stat_buf->st_size / dev->sector_size;
	} else if (S_ISBLK(stat_buf->st_mode)) {
#ifdef BLKSSZGET
		if (ioctl(fd, BLKSSZGET, &sector_size) < 0)
			MSG(0, "\tError: Using the default sector size\n");
		else if (dev->sector_size < sector_size)
			dev->sector_size = sector_size;
#endif
#ifdef BLKGETSIZE64
		if (ioctl(fd, BLKGETSIZE64, &dev->total_sectors) < 0) {
			MSG(0, "\tError: Cannot get the device size\n");
			free(stat_buf);
			return -1;
		}
#else
		if (ioctl(fd, BLKGETSIZE, &total_sectors) < 0) {
			MSG(0, "\tError: Cannot get the device size\n");
			free(stat_buf);
			return -1;
		}
		dev->total_sectors = total_sectors;
#endif
		dev->total_sectors /= dev->sector_size;

		if (i == 0) {
#ifdef HDIO_GETGIO
			if (ioctl(fd, HDIO_GETGEO, &geom) < 0)
				c.start_sector = 0;
			else
				c.start_sector = geom.start;
#else
			c.start_sector = 0;
#endif
		}

#if !defined(WITH_ANDROID) && defined(__linux__)
		/* Send INQUIRY command */
		memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
		io_hdr.interface_id = 'S';
		io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
		io_hdr.dxfer_len = sizeof(reply_buffer);
		io_hdr.dxferp = reply_buffer;
		io_hdr.cmd_len = sizeof(model_inq);
		io_hdr.cmdp = model_inq;
		io_hdr.timeout = 1000;

		if (!ioctl(fd, SG_IO, &io_hdr)) {
			int i = 16;

			MSG(0, "Info: [%s] Disk Model: ",
					dev->path);
			while (reply_buffer[i] != '`' && i < 80)
				printf("%c", reply_buffer[i++]);
			printf("\n");
		}
#endif
	} else {
		MSG(0, "\tError: Volume type is not supported!!!\n");
		free(stat_buf);
		return -1;
	}

	if (!c.sector_size) {
		c.sector_size = dev->sector_size;
		c.sectors_per_blk = F2FS_BLKSIZE / c.sector_size;
	} else if (c.sector_size != c.devices[i].sector_size) {
		MSG(0, "\tError: Different sector sizes!!!\n");
		free(stat_buf);
		return -1;
	}

#if !defined(WITH_ANDROID) && defined(__linux__)
	if (S_ISBLK(stat_buf->st_mode))
		f2fs_get_zoned_model(i);

	if (dev->zoned_model != F2FS_ZONED_NONE) {
		if (dev->zoned_model == F2FS_ZONED_HM)
			c.zoned_model = F2FS_ZONED_HM;

		if (f2fs_get_zone_blocks(i)) {
			MSG(0, "\tError: Failed to get number of blocks per zone\n");
			free(stat_buf);
			return -1;
		}

		if (f2fs_check_zones(i)) {
			MSG(0, "\tError: Failed to check zone configuration\n");
			free(stat_buf);
			return -1;
		}
		MSG(0, "Info: Host-%s zoned block device:\n",
				(dev->zoned_model == F2FS_ZONED_HA) ?
					"aware" : "managed");
		MSG(0, "      %u zones, %u randomly writeable zones\n",
				dev->nr_zones, dev->nr_rnd_zones);
		MSG(0, "      %lu blocks per zone\n",
				dev->zone_blocks);
	}
#endif
	/* adjust wanted_total_sectors */
	if (c.wanted_total_sectors != -1) {
		MSG(0, "Info: wanted sectors = %"PRIu64" (in %"PRIu64" bytes)\n",
				c.wanted_total_sectors, c.wanted_sector_size);
		if (c.wanted_sector_size == -1) {
			c.wanted_sector_size = dev->sector_size;
		} else if (dev->sector_size != c.wanted_sector_size) {
			c.wanted_total_sectors *= c.wanted_sector_size;
			c.wanted_total_sectors /= dev->sector_size;
		}
	}

	c.total_sectors += dev->total_sectors;
	free(stat_buf);
	return 0;
}

#else

#include "windows.h"
#include "winioctl.h"

#if (_WIN32_WINNT >= 0x0500)
#define HAVE_GET_FILE_SIZE_EX 1
#endif

static int win_get_device_size(const char *file, uint64_t *device_size)
{
	HANDLE dev;
	PARTITION_INFORMATION pi;
	DISK_GEOMETRY gi;
	DWORD retbytes;
#ifdef HAVE_GET_FILE_SIZE_EX
	LARGE_INTEGER filesize;
#else
	DWORD filesize;
#endif /* HAVE_GET_FILE_SIZE_EX */

	dev = CreateFile(file, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE ,
			NULL,  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,  NULL);

	if (dev == INVALID_HANDLE_VALUE)
		return EBADF;
	if (DeviceIoControl(dev, IOCTL_DISK_GET_PARTITION_INFO,
				&pi, sizeof(PARTITION_INFORMATION),
				&pi, sizeof(PARTITION_INFORMATION),
				&retbytes, NULL)) {

		*device_size = 	pi.PartitionLength.QuadPart;

	} else if (DeviceIoControl(dev, IOCTL_DISK_GET_DRIVE_GEOMETRY,
				&gi, sizeof(DISK_GEOMETRY),
				&gi, sizeof(DISK_GEOMETRY),
				&retbytes, NULL)) {

		*device_size = gi.BytesPerSector *
			gi.SectorsPerTrack *
			gi.TracksPerCylinder *
			gi.Cylinders.QuadPart;

#ifdef HAVE_GET_FILE_SIZE_EX
	} else if (GetFileSizeEx(dev, &filesize)) {
		*device_size = filesize.QuadPart;
	}
#else
	} else {
		filesize = GetFileSize(dev, NULL);
		if (INVALID_FILE_SIZE != filesize)
			return -1;
		*device_size = filesize;
	}
#endif /* HAVE_GET_FILE_SIZE_EX */

	CloseHandle(dev);
	return 0;
}

int get_device_info(int i)
{
	struct device_info *dev = c.devices + i;
	uint64_t device_size = 0;
	int32_t fd = 0;

	/* Block device target is not supported on Windows. */
	if (!c.sparse_mode) {
		if (win_get_device_size(dev->path, &device_size)) {
			MSG(0, "\tError: Failed to get device size!\n");
			return -1;
		}
	} else {
		device_size = c.device_size;
	}
	if (c.sparse_mode) {
		fd = open((char *)dev->path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	} else {
		fd = open((char *)dev->path, O_RDWR | O_BINARY);
	}
	if (fd < 0) {
		MSG(0, "\tError: Failed to open the device!\n");
		return -1;
	}
	dev->fd = fd;
	dev->total_sectors = device_size / dev->sector_size;
	c.start_sector = 0;
	c.sector_size = dev->sector_size;
	c.sectors_per_blk = F2FS_BLKSIZE / c.sector_size;
	c.total_sectors += dev->total_sectors;

	return 0;
}
#endif

int f2fs_get_device_info(void)
{
	int i;

	for (i = 0; i < c.ndevs; i++)
		if (get_device_info(i))
			return -1;

	if (c.wanted_total_sectors < c.total_sectors) {
		MSG(0, "Info: total device sectors = %"PRIu64" (in %u bytes)\n",
				c.total_sectors, c.sector_size);
		c.total_sectors = c.wanted_total_sectors;
		c.devices[0].total_sectors = c.total_sectors;
	}
	if (c.total_sectors * c.sector_size >
		(u_int64_t)F2FS_MAX_SEGMENT * 2 * 1024 * 1024) {
		MSG(0, "\tError: F2FS can support 16TB at most!!!\n");
		return -1;
	}

	for (i = 0; i < c.ndevs; i++) {
		if (c.devices[i].zoned_model != F2FS_ZONED_NONE) {
			if (c.zone_blocks &&
				c.zone_blocks != c.devices[i].zone_blocks) {
				MSG(0, "\tError: not support different zone sizes!!!\n");
				return -1;
			}
			c.zone_blocks = c.devices[i].zone_blocks;
		}
	}

	/*
	 * Align sections to the device zone size
	 * and align F2FS zones to the device zones.
	 */
	if (c.zone_blocks) {
		c.segs_per_sec = c.zone_blocks / DEFAULT_BLOCKS_PER_SEGMENT;
		c.secs_per_zone = 1;
	} else {
		c.zoned_mode = 0;
	}

	c.segs_per_zone = c.segs_per_sec * c.secs_per_zone;

	MSG(0, "Info: Segments per section = %d\n", c.segs_per_sec);
	MSG(0, "Info: Sections per zone = %d\n", c.secs_per_zone);
	MSG(0, "Info: sector size = %u\n", c.sector_size);
	MSG(0, "Info: total sectors = %"PRIu64" (%"PRIu64" MB)\n",
				c.total_sectors, (c.total_sectors *
					(c.sector_size >> 9)) >> 11);
	return 0;
}
