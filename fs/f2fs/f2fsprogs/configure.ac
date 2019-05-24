#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])

# Get version from file VERSION
m4_define([f2fs_tools_version], m4_esyscmd([sed -n '1p' VERSION | tr -d '\n']))
m4_define([f2fs_tools_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))
m4_define([f2fs_tools_gitdate],
		m4_esyscmd([git log -1 --pretty=format:%ci 2> /dev/null]))

AC_INIT([F2FS tools], [f2fs_tools_version],
			[linux-f2fs-devel@lists.sourceforge.net])

AC_DEFINE([F2FS_TOOLS_VERSION], "f2fs_tools_version", [f2fs-tools version])
AC_DEFINE([F2FS_MAJOR_VERSION], m4_bpatsubst(f2fs_tools_version,
				[\([0-9]*\)\(\w\|\W\)*], [\1]),
				[Major version for f2fs-tools])
AC_DEFINE([F2FS_MINOR_VERSION], m4_bpatsubst(f2fs_tools_version,
				[\([0-9]*\).\([0-9]*\)\(\w\|\W\)*], [\2]),
				[Minor version for f2fs-tools])

AC_CHECK_FILE(.git,
	AC_DEFINE([F2FS_TOOLS_DATE],
		"m4_bpatsubst(f2fs_tools_gitdate,
		[\([0-9-]*\)\(\w\|\W\)*], [\1])",
		[f2fs-tools date based on Git commits]),
	AC_DEFINE([F2FS_TOOLS_DATE],
		"f2fs_tools_date",
		[f2fs-tools date based on Source releases]))

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign tar-pax dist-xz])

# Test configure options.
AC_ARG_WITH([selinux],
	AS_HELP_STRING([--without-selinux],
	  [Ignore presence of libselinux and disable selinux support]))

AC_ARG_WITH([blkid],
	AS_HELP_STRING([--without-blkid],
	  [Ignore presence of libblkid and disable blkid support]))

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PATH_PROG([LDCONFIG], [ldconfig],
       [AC_MSG_ERROR([ldconfig not found])],
       [$PATH:/sbin])

# Checks for libraries.
PKG_CHECK_MODULES([libuuid], [uuid])

AS_IF([test "x$with_selinux" != "xno"],
	[PKG_CHECK_MODULES([libselinux], [libselinux],
	                   [have_selinux=yes], [have_selinux=no])],
	[have_selinux=no]
)

AS_IF([test "x$have_selinux" = "xyes"],
	[AC_DEFINE([HAVE_LIBSELINUX], [1], [Use libselinux])],
	[AS_IF([test "x$with_selinux" = "xyes"],
		[AC_MSG_ERROR([selinux support requested but libselinux not found])]
	)]
)

AS_IF([test "x$with_blkid" != "xno"],
	[PKG_CHECK_MODULES([libblkid], [blkid],
	                   [have_blkid=yes], [have_blkid=no])],
	[have_blkid=no]
)

AS_IF([test "x$have_blkid" = "xyes"],
	[AC_DEFINE([HAVE_LIBBLKID], [1], [Use blkid])],
	[AS_IF([test "x$with_blkid" = "xyes"],
		[AC_MSG_ERROR([blkid support requested but libblkid not found])]
	)]
)

# Checks for header files.
AC_CHECK_HEADERS(m4_flatten([
	attr/xattr.h
	byteswap.h
	fcntl.h
	linux/blkzoned.h
	linux/falloc.h
	linux/fs.h
	linux/hdreg.h
	linux/limits.h
	linux/posix_acl.h
	linux/types.h
	linux/xattr.h
	mntent.h
	scsi/sg.h
	stdlib.h
	string.h
	sys/acl.h
	sys/ioctl.h
	sys/syscall.h
	sys/mount.h
	sys/sysmacros.h
	sys/utsname.h
	sys/xattr.h
	unistd.h
]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_CHECK_FUNCS_ONCE([
	add_key
	fallocate
	fsetxattr
	fstat
	fstat64
	getmntent
	keyctl
	llseek
	lseek64
	memset
	setmntent
])

AS_IF([test "$ac_cv_header_byteswap_h" = "yes"],
      [AC_CHECK_DECLS([bswap_64],,,[#include <byteswap.h>])])

dnl
dnl Check to see if llseek() is declared in unistd.h.  On some libc's
dnl it is, and on others it isn't..... Thank you glibc developers....
dnl
AC_CHECK_DECL(llseek,[AC_DEFINE(HAVE_LLSEEK_PROTOTYPE, 1,
			[Define to 1 if llseek declared in unistd.h])],,
			[#include <unistd.h>])
dnl
dnl Check to see if lseek64() is declared in unistd.h.  Glibc's header files
dnl are so convoluted that I can't tell whether it will always be defined,
dnl and if it isn't defined while lseek64 is defined in the library,
dnl disaster will strike.
dnl
dnl Warning!  Use of --enable-gcc-wall may throw off this test.
dnl
dnl
AC_CHECK_DECL(lseek64,[AC_DEFINE(HAVE_LSEEK64_PROTOTYPE, 1,
		[Define to 1 if lseek64 declared in unistd.h])],,
		[#define _LARGEFILE_SOURCE
		#define _LARGEFILE64_SOURCE
		#include <unistd.h>])
dnl
dnl Word sizes...
dnl

# AC_CANONICAL_HOST is needed to access the 'host_os' variable
AC_CANONICAL_HOST

build_linux=no
build_windows=no
build_mac=no

# Detect the target system
case "${host_os}" in
linux*)
	build_linux=yes
	;;
cygwin*|mingw*)
	build_windows=yes
	;;
darwin*)
	build_mac=yes
	;;
*)
	AC_MSG_ERROR(["OS $host_os is not supported"])
	;;
esac

# Pass the conditionals to automake
AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([WINDOWS], [test "$build_windows" = "yes"])
AM_CONDITIONAL([OSX], [test "$build_mac" = "yes"])

# Install directories
#AC_PREFIX_DEFAULT([/usr])
#AC_SUBST([sbindir], [/sbin])
#AC_SUBST([sysconfdir], [/etc])
#AC_SUBST([localstatedir], [/var])
AC_CONFIG_FILES([
	Makefile
	man/Makefile
	lib/Makefile
	mkfs/Makefile
	fsck/Makefile
	tools/Makefile
	tools/sg_write_buffer/Makefile
])

# export library version info for mkfs/libf2fs_format_la
AC_SUBST(FMT_CURRENT, 3)
AC_SUBST(FMT_REVISION, 0)
AC_SUBST(FMT_AGE, 0)

# export library version info for lib/libf2fs_la
AC_SUBST(LIBF2FS_CURRENT, 4)
AC_SUBST(LIBF2FS_REVISION, 0)
AC_SUBST(LIBF2FS_AGE, 0)

AC_OUTPUT
