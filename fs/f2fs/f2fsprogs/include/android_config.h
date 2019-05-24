#if defined(__linux__)
#define HAVE_BYTESWAP_H 1
#define HAVE_FCNTL_H 1
#define HAVE_FALLOC_H 1
#define HAVE_LINUX_HDREG_H 1
#define HAVE_LINUX_LIMITS_H 1
#define HAVE_POSIX_ACL_H 1
#define HAVE_LINUX_TYPES_H 1
#define HAVE_LINUX_XATTR_H 1
#define HAVE_MNTENT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_SYSCALL_H 1
#define HAVE_SYS_MOUNT_H 1
#define HAVE_SYS_UTSNAME_H 1
#define HAVE_SYS_SYSMACROS_H 1
#define HAVE_SYS_XATTR_H 1
#define HAVE_UNISTD_H 1

#define HAVE_ADD_KEY 1
#define HAVE_FALLOCATE 1
#define HAVE_FSETXATTR 1
#define HAVE_FSTAT 1
#define HAVE_FSTAT64 1
#define HAVE_GETMNTENT 1
#define HAVE_KEYCTL 1
#define HAVE_LLSEEK 1
#define HAVE_LSEEK64 1
#define HAVE_MEMSET 1
#define HAVE_SETMNTENT 1

#ifdef WITH_SLOAD
#define HAVE_LIBSELINUX 1
#endif
#endif

#if defined(__APPLE__)
#define HAVE_FCNTL_H 1
#define HAVE_FALLOC_H 1
#define HAVE_POSIX_ACL_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_SYSCALL_H 1
#define HAVE_SYS_MOUNT_H 1
#define HAVE_SYS_UTSNAME_H 1
#define HAVE_SYS_XATTR_H 1
#define HAVE_UNISTD_H 1

#define HAVE_ADD_KEY 1
#define HAVE_FALLOCATE 1
#define HAVE_FSETXATTR 1
#define HAVE_FSTAT 1
#define HAVE_FSTAT64 1
#define HAVE_GETMNTENT 1
#define HAVE_KEYCTL 1
#define HAVE_LLSEEK 1
#define HAVE_MEMSET 1

#ifdef WITH_SLOAD
#define HAVE_LIBSELINUX 1
#endif
#endif

#if defined(_WIN32)
#define HAVE_LSEEK64
#endif
