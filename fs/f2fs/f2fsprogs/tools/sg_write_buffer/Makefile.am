## Makefile.am

if LINUX
AM_CPPFLAGS = -I./include
AM_CFLAGS = -Wall
sbin_PROGRAMS = sg_write_buffer
sg_write_buffer_SOURCES = sg_write_buffer.c \
	sg_cmds_basic.c		\
	sg_cmds_basic2.c	\
	sg_cmds_extra.c		\
	sg_cmds_mmc.c		\
	sg_io_linux.c		\
	sg_lib.c		\
	sg_lib_data.c		\
	sg_pt_common.c		\
	sg_pt_linux.c		\
	sg_pt_linux_nvme.c
endif
