/**
    program_test.cpp
    Purpose: doing some internal testing here
	Usage:
		./program_show [serialized testcase path]
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>

#include <iostream>

#include "Program.hpp"

int main(int argc, char *argv[]) {

	if (argc != 2 && argc != 3)
		return 1;

	char *path = argv[1];
	bool mem = argc == 3;
	char *buffer;
	struct stat st;

	srand(time(NULL));
	
	Program *program;
	program = Program::deserialize(path);

	// program->show();
	for (int i = 0; i < 10; i++)
		std::cout << program->rand_path() << '\n';		

	delete program;

	return 0;
}
