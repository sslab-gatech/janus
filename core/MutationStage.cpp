#include "MutationStage.hpp"
#include "Constants.hpp"
#include <cassert>
#include <cstring>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <random>
#include <unordered_set>
#include <stack>

#define CRAZY_MODE 

KnownSyscalls::KnownSyscalls() {
    add(SYS_read);
    add(SYS_write);
    add(SYS_open);
    add(SYS_lseek);
    // add(SYS_mmap);
    add(SYS_getdents64);
    add(SYS_pread64);
    add(SYS_pwrite64);
    add(SYS_stat);
    add(SYS_lstat);
    add(SYS_rename);
    add(SYS_fsync);
    add(SYS_fdatasync);
    // add(SYS_syncfs);
    // add(SYS_sendfile);
    add(SYS_access);
    add(SYS_ftruncate);
    add(SYS_truncate);
    // add(SYS_fstat);
    // add(SYS_statfs);
    // add(SYS_fstatfs);
    add(SYS_utimes);
    add(SYS_mkdir);
    add(SYS_rmdir);
    add(SYS_link);
    add(SYS_unlink);
    add(SYS_symlink);
    add(SYS_readlink);
    add(SYS_chmod);
    // add(SYS_fchmod);
    add(SYS_setxattr);
	add(SYS_fallocate);
	add(SYS_listxattr);
	add(SYS_removexattr);
}

MutationStage::MutationStage(uint8_t* seed, uint32_t len) {

    // take the input
    this->seed.serial_len = len;
    this->seed.serial = new uint8_t[len];
    memcpy(this->seed.serial, seed, len);

    this->seed.parsed = Program::deserialize(seed, len);
    this->stage_max = 1;

    // metadata for staging

    auto syscalls = this->seed.parsed->syscalls;
    for(auto it = syscalls.begin(); it != syscalls.end(); it++) {
		uint32_t syscall_nr = (*it)->nr;
        // if (KnownSyscalls.has(syscall_nr) && ImmutableSyscalls.find(syscall_nr) == ImmutableSyscalls.end()) {
        if (ImmutableSyscalls.find(syscall_nr) == ImmutableSyscalls.end()) {
            SyscallMutator* mutator = SyscallMutator::create(this->seed.parsed, *it);
            if (mutator) {
                syscallsToMutate.push_back(mutator);
            }
        }
    }

}

MutationStage::~MutationStage() {
    SyscallMutator *sm;
    for (std::vector<SyscallMutator*>::iterator it = syscallsToMutate.begin();
        it != syscallsToMutate.end(); it++) {
      sm = *it;
      delete sm;
    }
    syscallsToMutate.clear();
    delete seed.parsed;
    delete[] seed.serial;
}

HavocStage::HavocStage(uint8_t* seed, uint32_t len) 
    : MutationStage(seed,len) {
        this->stage_cur = 0;
}

HavocStage::~HavocStage() {
		;
}

void HavocStage::setStageMax(uint32_t stage_max) {
    assert(stage_cur == 0 && "set it only at the beginning!");
    this->stage_max = stage_max;
}

//from AFL
#define MUTATE_STACK_POW2       5
#define GENERATE_STACK_POW2     3

uint32_t HavocStage::mutate(uint8_t* buf, uint32_t buf_size) {

    uint32_t ret;
    size_t num_syscalls = syscallsToMutate.size();
    size_t syscall_to_mutate;
    std::stack<size_t> mutator_stack;

    uint32_t mutation_stack = 1 << (1 + rand32(0, MUTATE_STACK_POW2));

    for(uint32_t i = 0; i < mutation_stack; i++) {

        // pick random syscall and call havoc
        num_syscalls = syscallsToMutate.size();
        if (num_syscalls != 0) {
            syscall_to_mutate = rand32(0, num_syscalls);
            syscallsToMutate[syscall_to_mutate]->havoc();

            mutator_stack.push(syscall_to_mutate);
            break;
        }

    }

    ret = seed.parsed->serialize(buf, buf_size);
    while (!mutator_stack.empty()) {
        syscallsToMutate[mutator_stack.top()]->revert();
        mutator_stack.pop();
    }
    
    stage_cur += 1;
    return ret;
}

uint32_t HavocStage::generate(uint8_t* buf, uint32_t buf_size) {

    uint32_t ret;
    SyscallMutator *new_sm;
    std::stack<SyscallMutator*> generator_stack;

    uint32_t mutation_stack = 1 << (1 + rand32(0, GENERATE_STACK_POW2));
    for(uint32_t i = 0; i < mutation_stack; i++) {
        
        // add a syscall with havoc value
        // currently just add - test - remove
        new_sm = appendRandomSyscall();
        generator_stack.push(new_sm);
    
    }

    ret = seed.parsed->serialize(buf, buf_size);
    while (!generator_stack.empty()) {
        SyscallMutator *sm = generator_stack.top();
        sm->releaseTarget();
        delete sm;
        generator_stack.pop();
    }

    stage_cur += 1;
    return ret;
}


SyscallMutator *HavocStage::appendRandomSyscall() {

    // At this moment, we only append at havoc stage
    // Later we may have one separate, deterministic stage.

    Syscall* syscall = NULL;
    SyscallMutator *ret;

    do {
        int32_t nr = KnownSyscalls.get(rand32(0, KnownSyscalls.size()));

        ret = SyscallMutator::create_nr(this->seed.parsed, nr);

        if (ret) {
            syscall = ret->createTarget(ArgMap());

            if (!syscall) {
                delete ret;
                ret = NULL;
            } else {
                ret->setTarget(syscall);
            }
        }

    } while (!ret);

    return ret;
}

