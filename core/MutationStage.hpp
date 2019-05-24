#ifndef __MUTATIONSTAGE_H__
#define __MUTATIONSTAGE_H__


#include <list>
#include <vector>
#include <unordered_set>

#include "SyscallMutator.hpp"
#include "Constants.hpp"


// Describe syscalls that we support
// Mainly to pick one randomly.

static class KnownSyscalls {
    // std::unordered_set<uint32_t> set;
    std::vector<uint32_t> vector;

    private:
        void add(uint32_t nr) {
            // set.insert(nr);
            vector.push_back(nr);
        }

    public:
        KnownSyscalls();
    
        uint32_t get(size_t index) {
            return vector[index];
        }

        // uint32_t has(uint32_t nr) {
        //    return (set.find(nr) != set.end());
        // }

        size_t size(void) {
            return vector.size();
        }

} KnownSyscalls;

const std::unordered_set<uint32_t> ImmutableSyscalls = {
	SYS_open,
	SYS_rename,
	SYS_mkdir,
	SYS_rmdir,
	SYS_link,
	SYS_unlink,
	SYS_symlink,
	SYS_setxattr,
	SYS_listxattr,
	SYS_removexattr
};

// This class intends to describe a single mutation stage.
// AFL will create an object at each iteration and delete it
// Creating one and reusing (with reset in between) seems also OK but
// The current design doesn't seem to have too much performance cost.

class MutationStage {
    protected:
        struct {
            Program* parsed;
            uint8_t* serial;
            uint32_t serial_len;
        } seed;
        struct {
            Program* parsed;
        } mutated;
 
        uint32_t stage_max;

        std::vector<SyscallMutator*> syscallsToMutate;

    public:
        MutationStage() = delete;
        MutationStage(uint8_t* seed, uint32_t len);
        virtual ~MutationStage();

        virtual uint32_t mutate(uint8_t* buf, uint32_t buf_size) = 0;
        virtual uint32_t generate(uint8_t* buf, uint32_t buf_size) = 0;
        virtual uint32_t getStageMax() {return stage_max;}
};

/*
 * To add more create_syscall:
 * 0. Add XXXMutator at SyscallMutator;
 * 1. Add at KnownSyscalls::KnownSyscalls;
 * 2. Add at HavocStage::appendRandomSyscall;
 * 3. Add at SyscallMutator::create.
 */


// This is the main mutation stage that we care for now.
class HavocStage : public MutationStage {
    private:
        uint32_t stage_cur;
        SyscallMutator *appendRandomSyscall();

    public:
        HavocStage() = delete;
        HavocStage(uint8_t* seed, uint32_t len);
        ~HavocStage();
        uint32_t mutate(uint8_t* buf, uint32_t buf_size);
        uint32_t generate(uint8_t* buf, uint32_t buf_size);
        void setStageMax(uint32_t);

};


#endif
