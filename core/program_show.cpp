/**
    program_show.cpp
    Purpose: generate C code for a serialized testcase
	Usage:
		./program_show [serialized testcase path] [[mem]]
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "Program.hpp"

int main(int argc, char *argv[]) {

	if (argc != 2 && argc != 3)
		return 1;

	char *path = argv[1];
	bool mem = argc == 3;
	char *buffer;
	struct stat st;
	
	Program *program;
	if (!mem)
		program = Program::deserialize(path);
	else {
		lstat(path, &st);
		buffer = (char *)malloc(st.st_size);
		int fd = open(path, O_RDONLY);
		read(fd, buffer, st.st_size);
		close(fd);
		program = Program::deserialize((uint8_t *)buffer, (uint32_t)st.st_size);
	}

	program->show();
	delete program;

	return 0;
}
