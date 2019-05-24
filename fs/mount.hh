#ifndef FS_FUZZ_MOUNT_HH
#define FS_FUZZ_MOUNT_HH

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mount.h>
#include <linux/types.h>
#include <linux/loop.h>

#define die(...) do {               \
    fprintf(stderr, __VA_ARGS__);   \
                abort();            \
    } while (0)

static const char mount_point[] = "/mnt";
static const char loop_device[] = "/dev/loop1";

static void umount_it(void) {
  umount(mount_point);
}

static void mount_it(const char *fstype) {
	if (mount(loop_device, mount_point, fstype, 0x0, NULL) == -1 && errno == EACCES) {
		errno = 0;
		mount(loop_device, mount_point, fstype, MS_RDONLY, NULL);
	}
}

static int loop_setup(void)
{
	int loop_fd = open(loop_device, O_RDWR);
	if (loop_fd < 0) {
		die("Could not open loop device %s [%s]\n", loop_device, strerror(errno));
  }

  return loop_fd;
}

static void loop_detach(int loop_fd)
{
	ioctl(loop_fd, LOOP_CLR_FD, 0);
}

static void loop_attach(int loop_fd, const char* file)
{
	unsigned int max_nr_retry = 42;
	int file_fd = open(file, O_RDWR);
	if (file_fd < 0)
		die("Could not open file to attach %s [%s]\n", file, strerror(errno));

retry:
	if (ioctl(loop_fd, LOOP_SET_FD, file_fd)) {
		if (errno == EBUSY && --max_nr_retry)
			goto retry;
		die("Could not configure loop device %s with %s [%s]\n", loop_device, file, strerror(errno));
	}
	    
	close(file_fd);
}

static void loop_setinfo(int loop_fd, const char* file)
{
	static struct loop_info64 linfo;
	strncpy((char *)linfo.lo_file_name, file, sizeof(linfo.lo_file_name));
	ioctl(loop_fd, LOOP_SET_STATUS64, &linfo);
}

#endif 
