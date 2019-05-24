#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <lkl.h>
#include <lkl_host.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/syscall.h>

#define PAGE_SIZE 4096
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)

static const char doc_fsfuzz[] = "File system fuzzing program";
static const char args_doc_fsfuzz[] = "-t fstype -i fsimage";

static struct argp_option options[] = {
	{"enable-printk", 'p', 0, 0, "show Linux printks"},
	{"filesystem-type", 't', "string", 0, "select filesystem type - mandatory"},
	{"filesystem-image", 'i', "string", 0, "path to the filesystem image - mandatory"},
	{0},
};

static struct cl_args {
	int printk;
  int part;
	const char *fsimg_type;
	const char *fsimg_path;
} cla;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cl_args *cla = state->input;

	switch (key) {
	case 'p':
		cla->printk = 1;
		break;
	case 't':
		cla->fsimg_type = arg;
		break;
	case 'i':
		cla->fsimg_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp_fsfuzz = {
	.options = options,
	.parser = parse_opt,
	.args_doc = args_doc_fsfuzz,
	.doc = doc_fsfuzz,
};

static void activity(char *mpoint) {

  char *foo_bar_baz;
  char *foo_baz;
  char *xattr;
  char *hln;
  char *sln;
  int err;

  static int buf[8192];
  memset(buf, 0, sizeof(buf));

  err = asprintf(&foo_bar_baz, "%s/foo/bar/baz", mpoint);
  err = asprintf(&foo_baz, "%s/foo/baz", mpoint);
  err = asprintf(&xattr, "%s/foo/bar/xattr", mpoint);
  err = asprintf(&hln, "%s/foo/bar/hln", mpoint);
  err = asprintf(&sln, "%s/foo/bar/sln", mpoint);

  // opendir / readdir
  DIR *dir = (DIR *)lkl_opendir(mpoint, &err);
  if (dir) {
    lkl_readdir((struct lkl_dir *)dir);
    lkl_closedir((struct lkl_dir *)dir);
  }

  // open / mmap / read
  // mmap MAP_SHARED?
  int fd = lkl_sys_open(foo_bar_baz, LKL_O_RDONLY, 0);
  if (fd >= 0) {
    void *mem = lkl_sys_mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);

    if (mem != MAP_FAILED)
      lkl_sys_munmap((unsigned long)mem, 4096);

    lkl_sys_read(fd, (char *)buf, 11);
    lkl_sys_read(fd, (char *)buf, sizeof(buf));
    lkl_sys_close(fd);
  }

  // open / write / read
  fd = lkl_sys_open(foo_bar_baz, O_RDWR | O_TRUNC, 0777);
  if (fd >= 0) { 
    lkl_sys_write(fd, (char *)buf, 517); 
    lkl_sys_write(fd, (char *)buf, sizeof(buf)); 
    lkl_sys_fdatasync(fd);
    lkl_sys_fsync(fd);

    lkl_sys_lseek(fd, 0, SEEK_SET); 
    lkl_sys_read(fd, (char *)buf, sizeof(buf)); 
    lkl_sys_lseek(fd, 1234, SEEK_SET);
    lkl_sys_read(fd, (char *)buf, 517); 
    lkl_sys_close(fd); 
  } 

  // open / lseek / write / fallocate
  fd = lkl_sys_open(foo_bar_baz, O_RDWR | O_TRUNC, 0777);
  if (fd >= 0) {
	lkl_sys_lseek(fd, 1024 - 33, SEEK_SET);
	lkl_sys_write(fd, (char *)buf, sizeof(buf));
    lkl_sys_lseek(fd, 1024 * 1024 + 67, SEEK_SET);
    lkl_sys_write(fd, (char *)buf, sizeof(buf));
    lkl_sys_lseek(fd, 1024 * 1024 * 1024 - 113, SEEK_SET);
    lkl_sys_write(fd, (char *)buf, sizeof(buf));

    lkl_sys_lseek(fd, 0, SEEK_SET);
    lkl_sys_write(fd, (char *)buf, sizeof(buf));

    lkl_sys_fallocate(fd, 0, 0, 123871237);
    lkl_sys_fallocate(fd, 0, -13123, 123);
    lkl_sys_fallocate(fd, 0, 234234, -45897);
    lkl_sys_fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0, 4243261);
    lkl_sys_fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, -95713, 38447);
    lkl_sys_fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 18237, -9173);

    lkl_sys_close(fd);
  }

  // rename
  lkl_sys_rename(foo_bar_baz, foo_baz);
  
  // stat
  struct lkl_stat stat;
  memset(&stat, 0, sizeof(stat));
  lkl_sys_stat(foo_baz, &stat);

  // chmod / chown
  lkl_sys_chmod(foo_baz, 0000);
  lkl_sys_chmod(foo_baz, 1777);
  lkl_sys_chmod(foo_baz, 3777);
  lkl_sys_chmod(foo_baz, 7777);
  lkl_sys_chown(foo_baz, 0, 0);
  lkl_sys_chown(foo_baz, 1, 1);

  // unlink
  lkl_sys_unlink(foo_bar_baz);
  lkl_sys_unlink(foo_baz);

  // mknod
  lkl_sys_mknod(foo_baz, 0777, LKL_MKDEV(0, 0));

  // xattr
  char buf2[113];
  memset(buf2, 0, sizeof(buf2));
  lkl_sys_listxattr(xattr, buf2, sizeof(buf2));
  lkl_sys_removexattr(xattr, "user.mime_type");
  lkl_sys_setxattr(xattr, "user.md5", buf2, sizeof(buf2), XATTR_CREATE);
  lkl_sys_setxattr(xattr, "user.md5", buf2, sizeof(buf2), XATTR_REPLACE);

  // link
  lkl_sys_readlink(sln, buf2, sizeof(buf2));
  
}

struct arg_struct {
  long uffd;
  unsigned long base;
  void *buffer;
};

void *fault_handler_thread(void *arg) {
  struct arg_struct *args = (struct arg_struct *)arg;
  long uffd = args->uffd;
  void *buffer = args->buffer;
  unsigned long base = args->base;
  static struct uffd_msg msg;
  struct uffdio_copy uffdio_copy;
  ssize_t nread;

  for (;;) {
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    if (nready == -1)
      errExit("poll");

    nread = read(uffd, &msg, sizeof(msg));
    if (nread == 0 || nread == -1) {
      fprintf(stderr, "error read on userfaultfd!\n");
      _exit(1);
    }
    
    unsigned long offset = (msg.arg.pagefault.address & ~(PAGE_SIZE - 1)) - base;
    uffdio_copy.src = (unsigned long)(buffer) + offset;
    uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uffdio_copy.len = PAGE_SIZE;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) _exit(1);
  }
}

void *userfault_init(void *image_buffer, size_t size) {
  long uffd;
  size_t len = size;
  pthread_t thr;
  struct uffdio_register uffdio_register;
  struct uffdio_api uffdio_api;
  
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) 
    errExit("userfaultfd");
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    errExit("ioctl-UFFDIO_API");

  void *buffer = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buffer == MAP_FAILED)
    errExit("mmap");

  uffdio_register.range.start = (unsigned long) buffer;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) 
    errExit("register uffd");

  static struct arg_struct args;
  args.buffer = image_buffer;
  args.uffd = uffd;
  args.base = (unsigned long) buffer;
  int s = pthread_create(&thr, NULL, fault_handler_thread, (void *)(&args));
  if (s != 0) 
    errExit("pthread_create");

  return buffer;
}

extern void __afl_manual_init(void **buffer, size_t *size);
extern uint32_t __afl_in_trace;
// extern void output_edges(void);

int main(int argc, char **argv)
{
	struct lkl_disk disk;
	long ret;
	char mpoint[32];
	unsigned int disk_id;

  void *image_buffer;
  size_t size;

  struct stat st;

  if (argp_parse(&argp_fsfuzz, argc, argv, 0, 0, &cla) < 0)
    return -1;

	if (!cla.printk)
		lkl_host_ops.print = NULL;

  char *mount_options = NULL;
  if (!strcmp(cla.fsimg_type, "btrfs"))
    mount_options = "thread_pool=1";
  else if (!strcmp(cla.fsimg_type, "gfs2"))
    mount_options = "acl";
  else if (!strcmp(cla.fsimg_type, "reiserfs"))
    mount_options = "acl,user_xattr";
  else if (!strcmp(cla.fsimg_type, "ext4"))
    mount_options = "errors=remount-ro";

  if (!cla.fsimg_path) {
    __afl_manual_init(&image_buffer, &size); 
  } else {
    __afl_manual_init(NULL, NULL);
    lstat(cla.fsimg_path, &st); 
    int fd = open(cla.fsimg_path, O_RDWR);
    image_buffer = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    size = st.st_size;
  }

  disk.ops = NULL;
  disk.buffer = userfault_init(image_buffer, size);
  disk.capacity = size;

  ret = lkl_disk_add(&disk);
  if (ret < 0) {
      fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
      goto out;
  }
  disk_id = ret;

  lkl_start_kernel(&lkl_host_ops, "mem=128M");

  __afl_in_trace = 1;  

  ret = lkl_mount_dev(disk_id, cla.part, cla.fsimg_type, 0,
			                mount_options, mpoint, sizeof(mpoint));
	if (ret) {
		fprintf(stderr, "can't mount disk: %s\n", lkl_strerror(ret));
		goto disk_remove;
	}

  activity(mpoint);

  ret = lkl_umount_dev(disk_id, cla.part, 0, 1000);

  __afl_in_trace = 0;

disk_remove:
  lkl_disk_remove(disk);

out:
  lkl_sys_halt();

  // output_edges();

  return 0;
}
