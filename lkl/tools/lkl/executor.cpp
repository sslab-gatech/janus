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
#include <sys/syscall.h>

#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>

#include <vector>

#include "executor.hpp"
#include "Program.hpp"

#define PAGE_SIZE 4096
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)

static const char doc_executor[] = "File system fuzzing executor";
static const char args_doc_executor[] = "-t fstype -i fsimage -p program";

static struct argp_option options[] = {
	{"enable-printk", 'v', 0, 0, "show Linux printks"},
	{"filesystem-type", 't', "string", 0, "select filesystem type - mandatory"},
	{"filesystem-image", 'i', "string", 0, "path to the filesystem image - mandatory"},
	{"serialized-program", 'p', "string", 0, "serialized program - mandatory"},
	{0},
};

static struct cl_args {
	int printk;
  	int part;
	const char *fsimg_type;
	const char *fsimg_path;
	const char *prog_path;
} cla;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cl_args *cla = (struct cl_args*)state->input;

	switch (key) {
	case 'v':
		cla->printk = 1;
		break;
	case 't':
		cla->fsimg_type = arg;
		break;
	case 'i':
		cla->fsimg_path = arg;
		break;
	case 'p':
		cla->prog_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp_executor = {
	.options = options,
	.parser = parse_opt,
	.args_doc = args_doc_executor,
	.doc = doc_executor,
};

static void exec_syscall(Program *prog, Syscall *syscall) {

	long params[6];
	long ret;
	int cnt = 0;

	for (Arg *arg : syscall->args) {
		if (!arg->is_variable)
			params[cnt] = arg->value;
		else {
			Variable *v = prog->variables[arg->index];
			if (v->is_pointer() && v->value == 0)
				v->value = static_cast<uint8_t*>(malloc(v->size));
			params[cnt] = reinterpret_cast<long>(v->value);
		}
		cnt++;
	}

	ret = lkl_syscall(lkl_syscall_nr[syscall->nr], params);
	if (syscall->ret_index != -1)
		prog->variables[syscall->ret_index]->value = reinterpret_cast<uint8_t*>(ret);

	// show_syscall(prog, syscall);
	// printf("ret: %ld\n", ret);
}

static void close_active_fds(Program *prog) {
	
	long params[6];

	for (int64_t fd_index : prog->active_fds) {
		params[0] = reinterpret_cast<long>(prog->variables[fd_index]->value);
		lkl_syscall(lkl_syscall_nr[SYS_close], params);
	}

}

/*
static void activity() {

	static int buf[8192];
	long params[6];

	char filename[] = ".";

	params[0] = (long)(&filename);
	params[1] = O_RDONLY | O_DIRECTORY;
	params[2] = 0;

	// int fd = lkl_sys_open("foo/bar/baz", O_RDONLY, 0);
	int fd = lkl_syscall(lkl_syscall_nr[SYS_open], params);
	printf("%d\n", fd);
	if (fd >= 0) {
		lkl_sys_read(fd, (char *)buf, 1384);
	}
	lkl_sys_close(fd);
	printf("%s\n", buf);
	
}
*/

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

extern uint32_t __afl_in_trace;
extern "C" void __afl_manual_init_syscall(void);
// extern "C" void output_edges(void);

int main(int argc, char **argv)
{
	struct lkl_disk disk;
	long ret;
	char mpoint[32];
	unsigned int disk_id;
    
    void *image_buffer;
    size_t size;
	struct stat st;

	if (argp_parse(&argp_executor, argc, argv, 0, 0, &cla) < 0)
		return -1;

    if (!cla.fsimg_path) {
        printf("Please provide image through -i.\n");
        return -1;
    }

	if (!cla.printk)
		lkl_host_ops.print = NULL;

    const char *mount_options = NULL;
    if (!strcmp(cla.fsimg_type, "btrfs"))
        mount_options = "thread_pool=1";
    else if (!strcmp(cla.fsimg_type, "gfs2"))
        mount_options = "acl";
    else if (!strcmp(cla.fsimg_type, "reiserfs"))
        mount_options = "acl,user_xattr";
    else if (!strcmp(cla.fsimg_type, "ext4"))
        mount_options = "errors=remount-ro";
     
    /* set up for coming image */
    lstat(cla.fsimg_path, &st); 
    int fd = open(cla.fsimg_path, O_RDWR);
    if (fd < 0) return -1;
    image_buffer = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	size = st.st_size;
    __afl_manual_init_syscall();

	disk.ops = NULL;
	disk.buffer = userfault_init(image_buffer, size);
	disk.capacity = size;
	
	ret = lkl_disk_add(&disk);
	if (ret < 0) {
		fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
		lkl_sys_halt();
    	return -1;
	}
	disk_id = ret;

	lkl_start_kernel(&lkl_host_ops, "mem=128M");
	
    __afl_in_trace = 1;  
  
	ret = lkl_mount_dev(disk_id, cla.part, cla.fsimg_type, 0,
			                mount_options, mpoint, sizeof(mpoint));
	if (ret) {
		fprintf(stderr, "can't mount disk: %s\n", lkl_strerror(ret));
		lkl_sys_halt();
    	return -1;
	}
	
	ret = lkl_sys_chdir(mpoint);
	if (ret) {
		fprintf(stderr, "can't chdir to %s: %s\n", mpoint,
			lkl_strerror(ret));
		lkl_umount_dev(disk_id, cla.part, 0, 1000);
		lkl_sys_halt();
    	return -1;
	}

	Program *prog = Program::deserialize(cla.prog_path, true);
	for (Syscall *syscall : prog->syscalls) {
		exec_syscall(prog, syscall);
	}
	close_active_fds(prog);

	ret = lkl_sys_chdir("/");

	lkl_umount_dev(disk_id, cla.part, 0, 1000);
    
    __afl_in_trace = 0;

  	lkl_disk_remove(disk);
	lkl_sys_halt();

    exit(0);

    // output_edges();

	return 0;
}
