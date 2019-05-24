#include "SyscallMutator.hpp"
#include "Constants.hpp"

SyscallMutator* SyscallMutator::create_nr(Program* program, int32_t nr) {
    // mutating.
    switch(nr) {
        case SYS_read: 
            return new ReadMutator(program);
        case SYS_write:
            return new WriteMutator(program);
        case SYS_open:
            return new OpenMutator(program);
        case SYS_lseek:
            return new LseekMutator(program);
        case SYS_mmap:
            return new MmapMutator(program); 
        case SYS_munmap:
            return new MunmapMutator(program); 
        case SYS_getdents64:
            return new Getdents64Mutator(program);
        case SYS_pread64:
            return new Pread64Mutator(program);
        case SYS_pwrite64:
            return new Pwrite64Mutator(program);
        case SYS_stat:
            return new StatMutator(program);
        case SYS_lstat:
            return new LstatMutator(program);
        case SYS_rename:
			return new RenameMutator(program);
        case SYS_fsync:
            return new FsyncMutator(program);
        case SYS_fdatasync:
            return new FdatasyncMutator(program);
        case SYS_syncfs:
            return new SyncfsMutator(program);
        case SYS_sendfile:
            return new Sendfile64Mutator(program);
        case SYS_access:
            return new AccessMutator(program);
        case SYS_ftruncate:
            return new FtruncateMutator(program);
        case SYS_truncate:
            return new TruncateMutator(program);
        case SYS_fstat:
            return new FstatMutator(program);
        case SYS_statfs:
            return new StatfsMutator(program);
        case SYS_fstatfs:
            return new FstatfsMutator(program);
        case SYS_utimes:
            return new UtimesMutator(program);
        case SYS_mkdir:
            return new MkdirMutator(program);
        case SYS_rmdir:
            return new RmdirMutator(program);
        case SYS_link:
            return new LinkMutator(program);
        case SYS_unlink:
            return new UnlinkMutator(program);
        case SYS_symlink:
            return new SymlinkMutator(program);
        case SYS_readlink:
            return new ReadlinkMutator(program);
        case SYS_chmod:
            return new ChmodMutator(program);
        case SYS_fchmod:
            return new FchmodMutator(program);
        case SYS_setxattr:
            return new SetxattrMutator(program);
		case SYS_fallocate:
			return new FallocateMutator(program);
		case SYS_listxattr:
			return new ListxattrMutator(program);
		case SYS_removexattr:
			return new RemovexattrMutator(program);
        default:
            fprintf(stderr,"unsupported syscall id: %d\n", nr);
            assert(0 && "unsupported syscall id");
            return NULL;
    }

}

SyscallMutator* SyscallMutator::create(Program* program, Syscall* syscall) {
    // For now this is called only when MutationStages create mutators from
    // seed program. There are another function for "appending" syscalls whiling
    SyscallMutator* ret = create_nr(program, syscall->nr);
    if (ret != NULL) {
        ret->setTarget(syscall);
    }
    return ret;
}

constexpr const uint32_t LseekMutator::whence_options[5];
constexpr const uint32_t AccessMutator::mode_options[4];
constexpr const uint32_t ChmodMutator::mode_options[12];
constexpr const uint32_t FchmodMutator::mode_options[12];
constexpr const int32_t MmapMutator::prot_options[4];
constexpr const int32_t MmapMutator::flags_options[7]; 
constexpr const uint32_t FallocateMutator::mode_options[6]; 
