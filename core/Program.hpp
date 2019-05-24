#ifndef _PROGRAM_HPP
#define _PROGRAM_HPP

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <algorithm>

#include <vector>
#include <map>
#include <algorithm>
#include <cassert>

#include "Image.hpp"

// Variable Type
#define LONG 	0x01
#define STRING  0x02
#define PUCHAR	0x03
#define PVOID   0x04
#define MMAP_BASE   0x05
#define UNKNOWN     0xff

// kind
#define NONE        0x00
/* The following four should match FILE, DIR, SYMLINK, and FIFO
 * will not work otherwise..  At least for now.*/
#define FD_FILE     I_FILE
#define FD_DIR      I_DIR
#define FD_SYMLINK  I_SYMLINK
#define FD_FIFO     I_FIFO

struct Variable {
	std::string name;
	uint8_t type;
	uint32_t size;
	uint8_t* value;

	// kind: what this variable is (fd, mmap base, etc)
	uint8_t kind;

	Variable() {
		value = nullptr;
        kind = UNKNOWN;
	}
	~Variable();
	bool is_pointer()
	{
		return type == PUCHAR || type == STRING;
	}
};

typedef std::map<size_t, int64_t> ArgMap;
struct Arg {
	// an argument is either a variable (e.g., int x;)
	// or a literal constant (10)
	// if constant, put it here. 
	// if variable, keep "index" here.
	// what is the "index"? program object has
	// a vector of variables. index is the index of
	// the variable in the vector.
	union {
		int64_t value;
		int64_t index;
	};
	uint8_t     is_variable;

	// For arg mutation, we don't want to mutate
	// things like fd. Let's mark those with a vector.

	Arg() {}
	Arg(int64_t value, uint8_t is_variable) : is_variable(is_variable)
	{
		if (is_variable)
			this->index = value;
		else
			this->value = value;
        //is_mutable = true; //true by default for now.
	}
    Arg(const Arg& arg) {
        if(arg.is_variable)
            index = arg.index;
        else
            value = arg.value;
        is_variable = arg.is_variable;
    }

    Arg& operator=(const Arg& other) {
        if(&other == this)
            return *this;

        if(other.is_variable)
            this->index = other.index;
        else
            this->value = other.value;
        this->is_variable = other.is_variable;
        return *this;
    }
};

struct Syscall {
	int32_t nr;
	std::vector<Arg*> args;
	// if we save return value, it must be a 
	// variable; 
	// if we do not care the return value,
	// by default it is -1.
	int64_t ret_index;

	~Syscall();
	Syscall(int32_t nr) : nr(nr), ret_index(-1) {}

   	Syscall(const Syscall& syscall) :
    	nr(syscall.nr), ret_index(syscall.ret_index) {
		for (auto a : syscall.args) 
			args.push_back(new Arg(*a));
    }

    Syscall operator=(const Syscall& syscall) {
		for (auto a : syscall.args) 
			args.push_back(new Arg(*a));
		nr = syscall.nr;
		ret_index = syscall.ret_index;
		return *this;
  	}

    Syscall(const Syscall&& syscall) = delete;

	void add_arg(Arg *arg) {
               args.push_back(arg);
   	}
};

struct Program {
    // To make Program more extensible, we need a vector of indices.

	std::vector<Variable*> variables;
	std::vector<Syscall*> syscalls;
        
        // the list of various variable indices.
        //std::vector<std::vector<int64_t>> variable_indices;

	std::vector<int64_t> active_fds;
	std::vector<int64_t> active_file_fds;
	std::vector<int64_t> active_dir_fds;

        std::vector<int64_t> active_map_base_idx; //bases of mmap'd memory
        //std::vector<int64_t> active_map_size; // should match with above

	std::vector<FileObject*> avail_files;
	std::vector<FileObject*> avail_dirs;
	std::vector<FileObject*> avail_non_dirs;
	std::map<FileObject*, int64_t> file_paths; // store variables for path of all file objects

	uint32_t variable_cnt;
    int64_t root_path_index;

	// by default, the first variable is
	// two two-page-size buffers for sending/receiving things from kernel
	static const int64_t src8192 = 0;
	static const int64_t dest8192 = 1;
	// v_2 .. v_n are variables for path
	static const int64_t path_start = 2;
	
	// pre-allocate the variables for all 
	void prepare_file_paths();
	void prepare_buffers();

	~Program();
	Program();

	// load testcase 
	// this should be used to load saved testcase 
	static Program *deserialize(const char *path, bool for_execution = false);
	static Program *deserialize(uint8_t *buf, uint32_t len);
	// for serialization
	// uint32_t calculate_size();
	// save testcase 
	bool serialize(const char *path);
	// return true if buffer not overflow
	uint32_t serialize(uint8_t *buf, uint32_t len);

	// create variable
	int64_t create_variable(uint8_t type, uint32_t size = 0, uint8_t *value = NULL, uint8_t fd_type = UNKNOWN);

    // add file fd
	void add_fd(int64_t fd_index) { 
		active_fds.push_back(fd_index); 
		if (variables[fd_index]->kind == FD_DIR)
			active_dir_fds.push_back(fd_index);
		else
			active_file_fds.push_back(fd_index);
	}

    void add_variable(Variable *v) {
        variables.push_back(v);
        switch (v->kind) {
            case FD_FILE:
            case FD_DIR:
            case FD_SYMLINK:
            case FD_FIFO:
                add_fd(variable_cnt);
                break;
            default:
                break;
        }
        variable_cnt++;
    }

	// remove variable
	// now we can only remove last variable
	void remove_last_variable() {
        //remove itself from lists..
        Variable *v = variables.back();
        assert(v != nullptr);
        switch(v->kind) {
            case NONE:
                break;
            case FD_FILE:
            case FD_DIR:
            case FD_SYMLINK:
            case FD_FIFO:
                assert(variable_cnt == variables.size());
                remove_fd(variable_cnt - 1);
                break;
            case MMAP_BASE:
                assert(variable_cnt == variables.size());
                mark_base_unmapped(variable_cnt - 1);
                break;
            case UNKNOWN:
                break;
            default:
                assert(0);
        }
		variables.pop_back();
		variable_cnt--;
		delete v;
	}
	
	// add syscall
	void add_syscall(Syscall *syscall) { syscalls.push_back(syscall); }

    // remove last syscall (unsafe)
    void remove_last_syscall() { 
        // should remove ret variable also
        // it should be the last one.
        // we still leave this in releaseTarget
        Syscall *syscall = syscalls.back();
        syscalls.pop_back();
        delete syscall;
    }

    // checked remove
    void remove_last_syscall(Syscall* syscall) {
        assert(syscalls.back() == syscall);
        remove_last_syscall();
    }

    // remove syscall
	void remove_syscall(Syscall *syscall) {
		syscalls.erase(std::remove(syscalls.begin(), syscalls.end(), syscall), syscalls.end());
	}

	// add file object
	void add_file(FileObject *fobj) { 
		avail_files.push_back(fobj); 
		if (fobj->type == I_DIR)
			avail_dirs.push_back(fobj);
		else
			avail_non_dirs.push_back(fobj);
	}

	// remove file object
	void remove_last_file() {
		FileObject *fobj = avail_files.back();
		avail_files.pop_back();
		if (fobj->type == I_DIR)
			avail_dirs.pop_back();
		else
			avail_non_dirs.pop_back();
		delete fobj;
	}

	void remove_file(FileObject *fobj) {
		avail_files.erase(std::remove(avail_files.begin(), avail_files.end(), fobj), avail_files.end());
		if (fobj->type == I_DIR)
			remove_dir(fobj);
		else
			remove_non_dir(fobj);
	}

	void remove_dir(FileObject *fobj) {
		avail_dirs.erase(std::remove(avail_dirs.begin(), avail_dirs.end(), fobj), avail_dirs.end());
	}

	void remove_non_dir(FileObject *fobj) {
		avail_non_dirs.erase(std::remove(avail_non_dirs.begin(), avail_non_dirs.end(), fobj), avail_non_dirs.end());
	}

	
    int64_t get_random_file_fd(void) {
        assert(active_file_fds.size() != 0);
        return active_file_fds[rand32(0, active_file_fds.size())];
    }

    int64_t get_random_dir_fd(void) {
        assert(active_dir_fds.size() != 0);
        return active_dir_fds[rand32(0, active_dir_fds.size())];
    }

    int64_t get_random_fd(void) {
		assert(active_fds.size() != 0);
        return active_fds[rand32(0, active_fds.size())];
    }

	// remove file fd
	void remove_fd(int64_t fd_index) {
		if (variables[fd_index]->kind == I_DIR)
			remove_dir_fd(fd_index);
		else
			remove_file_fd(fd_index);
		active_fds.erase(std::remove(active_fds.begin(), 
							active_fds.end(), fd_index), active_fds.end());
	}

	void remove_file_fd(int64_t fd_index) 
	{ 
		active_file_fds.erase(std::remove(active_file_fds.begin(), 
							active_file_fds.end(), fd_index), active_file_fds.end());
	}

	void remove_dir_fd(int64_t fd_index)
	{
		active_dir_fds.erase(std::remove(active_dir_fds.begin(), 
							active_dir_fds.end(), fd_index), active_dir_fds.end());
	}

    void mark_base_unmapped(int64_t map_index) {
        // upon calling munmap, base should not be a base any more.

        auto it = std::find(active_map_base_idx.begin(),
                active_map_base_idx.end(), map_index);
        assert(it != active_map_base_idx.end());
        variables[map_index]->kind = NONE;
        active_map_base_idx.erase(it);

    }

	FileObject *get_random_fobj(void) {
		assert(avail_files.size() != 0);
		return avail_files[rand32(0, avail_files.size())];
	}
	FileObject* get_random_dir() { 
		assert(avail_dirs.size() != 0);
		return avail_dirs[rand32(0, avail_dirs.size())]; 
	}
	FileObject* get_random_file() { 
		assert(avail_non_dirs.size() != 0);
		return avail_non_dirs[rand32(0, avail_non_dirs.size())]; 
	}
	std::string rand_path();

	void show();

};

void show_variable(Variable *v);
void show_syscall(Program *prog, Syscall *syscall);

#endif
