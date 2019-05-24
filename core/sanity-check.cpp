/*
 * For testing the syscall fuzzer for file system.
 * Take serialized program as an input
 * turn it into a source file using program_show
 * compile it using gcc
 * crash if it fails.
 */

#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cassert>
#include <cstring>

#include <iostream>

#include "Program.hpp"

using namespace std;


#define BUF_SIZE (32 * (1 << 10))
uint8_t buf[BUF_SIZE];

int main(int argc, char* argv[]) {

    ssize_t rc, len;
    char temp_file_name[50];
    strncpy(temp_file_name,"/tmp/fs-fuzz-sanity-XXXXXXXXX",50);
    int temp_fd = mkstemp(temp_file_name);

    len = read(STDIN_FILENO, buf, BUF_SIZE);
    if(len <= 0) {
        cout << "failed to read from stdin!\n" << endl;
        raise(SIGSEGV);
    }


    rc = write(temp_fd, (void*)buf, len);

    if(rc != len) {
        cout << "failed to write to temp_fd!\n" << endl;
        raise(SIGSEGV);
    }

    close(temp_fd);

    Program* program = Program::deserialize(temp_file_name);
    //Program* program = Program::deserialize("temp/corpus/open_1");


    strncpy(temp_file_name,"/tmp/fs-fuzz-sanity-XXXXXXXXX.c",50);
    temp_fd = mkstemps(temp_file_name,2);

    //string source_file_name("a.c");
    //int source_fd = open(source_file_name.c_str(), O_CREAT|O_RDWR|O_TRUNC, 0666);
    int escape = dup(STDOUT_FILENO);
    //dup2(STDOUT_FILENO,source_fd);
    dup2(temp_fd, STDOUT_FILENO);
    program->show();
    //printf("error");
    fflush(NULL);
    delete program;
    dup2(escape, STDOUT_FILENO);

    char cmd[100];
    strncpy(cmd,"gcc ",4);
    strncat(cmd,temp_file_name,50);
    int result = system(cmd);
    if( result != 0) {
        raise(SIGSEGV);
    }
    return 0;

}
