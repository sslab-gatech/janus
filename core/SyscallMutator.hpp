#include <cassert>
#include <string>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "Program.hpp"
#include "Utils.hpp"
#include "Constants.hpp"
#include <map>

/*
 * Too add more XXXMutator
 * 1. create XXXMutator class (refer to WriteMutator)
 * 2. register it at SyscallMutator::create (SyscallMutator.cpp)
 */

class SyscallMutator {

    protected:
        Program* program;
        Syscall* original;
        Syscall* target;

    public:
        SyscallMutator(Program* program, Syscall* syscall = NULL) {
            this->program = program;
            this->target = syscall;
            if (syscall) {
                original = new Syscall(syscall->nr);
                *original = *target;
            } else original = NULL;
        }

        void setTarget(Syscall *syscall) {
            this->target = syscall;
            original = new Syscall(syscall->nr);
            *original = *target;
        }

        Syscall *getTarget() {
            return this->target;
        }

        virtual void releaseTarget() {
            //XXX: why is mine always the last?
            program->remove_last_syscall(this->target);
            this->target = NULL;
            if (original) {
                delete this->original;
                original = NULL;
            }
        }

        static SyscallMutator* create(Program* program, Syscall* syscall = NULL);
        static SyscallMutator* create_nr(Program* program, int32_t nr);
        virtual Syscall* createTarget(const ArgMap &argMap) = 0;

        virtual ~SyscallMutator() {
            if (original)
                delete original;
        }

        virtual uint64_t getStageMax(void) {
            assert(0 && "unimplemented!");
        }
        virtual uint32_t mutate(void) {
            assert(0 && "unimplemented!");
        }
        virtual uint32_t revert(void) {
            //assert(0 && "unimplemented!");
            assert(original != nullptr && target != nullptr);
            for (size_t i = 0; i < original->args.size(); i+=1) {
                *(target->args[i]) = *(original->args[i]);
            }
        }
        virtual uint32_t havoc(void) {
            //if(target) printf("havoc not implemented for %d\n",target->nr);
            //else printf("havoc called for null target\n");
            //assert(0 && "unimplemented!");
            //XXX: BAD: silently not mutating...
            //TODO
        }
        virtual bool done(void) {
            assert(0 && "unimplemented!");
        }
};

class ReadMutator : public SyscallMutator {

    // ssize_t read(int fd, void *buf, size_t count); 
    private:
        struct {
            uint64_t max;
        } len;

    public:

        ReadMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                len.max = PAGE_SIZE; //XXX
            }
        virtual ~ReadMutator() {}

        virtual Syscall* createTarget(const ArgMap& argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall* ret = new Syscall(SYS_read);
            int64_t fd_index;

            auto it = argMap.find(0);
            if (it == argMap.end())
                fd_index = program->get_random_file_fd();
            else
                fd_index = it->second;

            ret->add_arg(new Arg(fd_index, 1));
            ret->add_arg(new Arg(Program::src8192, 1));
            ret->add_arg(new Arg(rand32(1, PAGE_SIZE * 2 + 1), 0));

            program->add_syscall(ret);
            return ret;
        }

        uint32_t havoc(void) {
            target->args[2]->value = rand32(0, len.max + 1);
            return 0;
        }
};

class WriteMutator : public SyscallMutator {
    //int open(const char *pathname, int flags, mode_t mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } len;

    public:
        WriteMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                this->len.max = PAGE_SIZE * 2;
                this->len.cur = 0;
            }
        virtual ~WriteMutator() {}

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *syscall = new Syscall(SYS_write);

            int64_t fd_index = program->get_random_file_fd();
            syscall->add_arg(new Arg(fd_index, 1));
            syscall->add_arg(new Arg(Program::dest8192, 1));
            syscall->add_arg(new Arg(rand32(1, PAGE_SIZE * 2 + 1), 0));

            program->add_syscall(syscall);
            return syscall;
        };


        virtual uint32_t havoc(void) { 
            target->args[2]->value = rand32(0,len.max+1);
        }

};

class LseekMutator : public SyscallMutator {
    // off_t lseek(int fd, off_t offset, int whence); 
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } offset;
        struct {
            uint32_t max = 4;
            uint32_t cur;
        } whence;
        static const constexpr uint32_t whence_options[5] = 
        {SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE};

    public:
        LseekMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                this->offset.max = PAGE_SIZE * 2;
                this->offset.cur = 0;
                this->whence.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *syscall = new Syscall(SYS_lseek);
            int64_t fd_index = program->get_random_file_fd();

            syscall->add_arg(new Arg(fd_index, 1));
            syscall->add_arg(new Arg(rand32(1, PAGE_SIZE + 1), 0));
            syscall->add_arg(new Arg(whence_options[rand32(0, sizeof(whence_options) / sizeof(uint32_t))], 0));

            program->add_syscall(syscall);
            return syscall;

        };

        virtual uint32_t havoc(void) { 
            target->args[1]->value = rand32(0,offset.max+1);
            target->args[2]->value = whence_options[rand32(0, sizeof(whence_options) / sizeof(uint32_t))];
            return 0;
        }

};

class Getdents64Mutator : public SyscallMutator {
    // int getdents64(unsigned int fd, struct linux_dirent64 *dirp,
    //                unsigned int count);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } count;

    public:
        Getdents64Mutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                count.max = PAGE_SIZE * 2;
                count.cur = 1;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_dir_fds.empty())
                return NULL;

            Syscall *syscall = new Syscall(SYS_getdents64);
            int64_t fd_index;

            auto it = argMap.find(0);
            if (it == argMap.end())
                fd_index = program->get_random_dir_fd();
            else
                fd_index = it->second;


            syscall->add_arg(new Arg(fd_index, 1));
            syscall->add_arg(new Arg(Program::dest8192, 1));
            syscall->add_arg(new Arg(rand32(0, PAGE_SIZE * 2 + 1), 0));
            syscall->ret_index = -1;

            program->add_syscall(syscall);
            return syscall;
        };

        uint32_t havoc(void) { 
            target->args[2]->value = rand32(0, PAGE_SIZE * 2 + 1);
            return 0;
        }

};

class Pread64Mutator : public SyscallMutator {

    // ssize_t read(int fd, void *buf, size_t count);
    private:
        struct {
            uint64_t max;
            uint64_t cur;
        } len;

        struct {
            uint64_t max;
            uint64_t cur;
        } offset;

        void __init_states(void) {
            len.max = PAGE_SIZE; //XXX
            len.cur = 0;
        }

    public:

        Pread64Mutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                __init_states();
                offset.max = PAGE_SIZE;
                offset.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall* ret = new Syscall(SYS_pread64);
            int64_t fd_index;

            auto it = argMap.find(0);
            if (it == argMap.end())
                fd_index = program->get_random_file_fd();
            else
                fd_index = it->second;

            ret->add_arg(new Arg(fd_index, 1));
            ret->add_arg(new Arg(Program::src8192, 1));
            ret->add_arg(new Arg(rand32(1, PAGE_SIZE * 2 + 1), 0));
            ret->add_arg(new Arg(rand32(1, PAGE_SIZE * 2 + 1), 0));

            program->add_syscall(ret);
            return ret;
        }


               uint32_t havoc(void) {
            //assert(0 && "unimplemented!");
            target->args[2]->value = rand32(0,len.max+1);
            target->args[3]->value = rand32(0,offset.max+1);
            return 0;
        }
        };

class Pwrite64Mutator : public SyscallMutator {
    //int open(const char *pathname, int flags, mode_t mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } len;

        struct {
            uint64_t max;
            uint64_t cur;
        } offset;

    public:
        Pwrite64Mutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                this->len.max = PAGE_SIZE * 2;
                this->len.cur = 0;
                offset.max = PAGE_SIZE;
                offset.cur = 0;
            }
        virtual ~Pwrite64Mutator() {}

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *syscall = new Syscall(SYS_pwrite64);

            int64_t fd_index = program->get_random_file_fd();
            syscall->add_arg(new Arg(fd_index, 1));
            syscall->add_arg(new Arg(Program::dest8192, 1));
            syscall->add_arg(new Arg(rand32(1,PAGE_SIZE * 2 + 1), 0));
            syscall->add_arg(new Arg(rand32(1,PAGE_SIZE * 2 + 1), 0));

            program->add_syscall(syscall);
            return syscall;
        };


        uint32_t havoc(void) {
            target->args[2]->value = rand32(0,len.max+1);
            target->args[3]->value = rand32(0,offset.max+1);
            return 0;
        }
        
};

class StatMutator : public SyscallMutator {
    // int stat(const char *pathname, struct stat *statbuf);
    private:
        struct {
            uint64_t max;
            uint64_t cur;
        } path;

    public:
        StatMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

            Syscall* ret = new Syscall(SYS_stat);
            FileObject *fobj = program->get_random_fobj();

            // arg1: path
            auto it = program->file_paths.find(fobj);
            assert(it != program->file_paths.end());
            ret->add_arg(new Arg(it->second, 1));

            // arg2: buffer
            ret->add_arg(new Arg(Program::dest8192, 1));

            program->add_syscall(ret);
            return ret;
        }

        uint32_t havoc(void) {
			if (program->avail_files.empty())
					return 0;
            target->args[0]->index = program->file_paths[program->get_random_fobj()];
            return 0;
        }
};

class LstatMutator : public SyscallMutator {
    // int lstat(const char *pathname, struct stat *statbuf);
    private:
        struct {
            uint64_t max;
            uint64_t cur;
        } path;

        void __init_status(void) {
            ;
        }

    public:

        LstatMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                __init_status();
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

            Syscall* ret = new Syscall(SYS_lstat);
            FileObject *fobj = program->get_random_fobj();

            // arg1: path
            auto it = program->file_paths.find(fobj);
            assert(it != program->file_paths.end());
            ret->add_arg(new Arg(it->second, 1));

            // arg2: buffer
            ret->add_arg(new Arg(Program::dest8192, 1));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->avail_files.empty())
				return 0;
            target->args[0]->index = program->file_paths[program->get_random_fobj()];
            return 0;
        }
};

class FsyncMutator : public SyscallMutator {
    // int fsync(int fd);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } fd;

    public:
        FsyncMutator(Program *program, Syscall *syscall = NULL) 
            : SyscallMutator(program, syscall) {
                fd.max = program->active_file_fds.size() - 1;
                fd.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *ret = new Syscall(SYS_fsync);

            int64_t fd_index = program->get_random_file_fd();
            ret->add_arg(new Arg(fd_index, 1));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->active_file_fds.empty())
				return 0;
            target->args[0]->index = program->get_random_file_fd();
			return 0;
        }
};

class FdatasyncMutator : public SyscallMutator {
    // int fdatasync(int fd);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } fd;

    public:
        FdatasyncMutator(Program *program, Syscall *syscall = NULL) 
            : SyscallMutator(program, syscall) {
                fd.max = program->active_file_fds.size() - 1;
                fd.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *ret = new Syscall(SYS_fdatasync);

            int64_t fd_index = program->get_random_file_fd();
            ret->add_arg(new Arg(fd_index, 1));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->active_file_fds.empty())
				return 0;
            target->args[0]->index = program->get_random_file_fd();
			return 0;
        }
};

class SyncfsMutator : public SyscallMutator {
    // int syncfs(int fd);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } fd;

    public:
        SyncfsMutator(Program *program, Syscall *syscall = NULL) 
            : SyscallMutator(program, syscall) {
                fd.max = program->active_file_fds.size() - 1;
                fd.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *ret = new Syscall(SYS_syncfs);

            int64_t fd_index = program->get_random_file_fd();
            ret->add_arg(new Arg(fd_index, 1));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->active_file_fds.empty())
				return 0;
            target->args[0]->index = program->get_random_file_fd();
			return 0;
        }
};

class Sendfile64Mutator : public SyscallMutator {
    // ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);	
    private:
        // struct {
        //	uint32_t max;
        //	uint32_t cur;
        // } offset;
        struct {
            uint32_t max;
            uint32_t cur;
        } count;

    public:
        Sendfile64Mutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                count.max = PAGE_SIZE * 2;
                count.cur = 1;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *ret = new Syscall(SYS_sendfile);

            int64_t out_fd_index = program->get_random_file_fd();
            ret->add_arg(new Arg(out_fd_index, 1));
            int64_t in_fd_index = program->get_random_file_fd();
            ret->add_arg(new Arg(in_fd_index, 1));
            ret->add_arg(new Arg(0, 0));
            ret->add_arg(new Arg(rand32(1, PAGE_SIZE * 2 + 1), 0));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
            target->args[3]->value = rand32(1, PAGE_SIZE * 2 + 1);
        }
};

class AccessMutator : public SyscallMutator {
    // int access(const char *pathname, int mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } path;
        struct {
            uint32_t max = 3;
            uint32_t cur;
        } mode;
        static const constexpr uint32_t mode_options[4] = {F_OK, R_OK, W_OK, X_OK};

    public:
        AccessMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
                mode.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_access);
            FileObject *fobj = program->get_random_fobj();

            // arg1: pathname
            auto it = program->file_paths.find(fobj);
            assert(it != program->file_paths.end());
            ret->add_arg(new Arg(it->second, 1));

            // arg2: buffer
            ret->add_arg(new Arg(mode_options[rand32(0, 4)], 0));

            program->add_syscall(ret);	
            return ret;	
        }

        uint32_t havoc(void) {
			if (program->avail_files.empty())
				return 0;
            target->args[0]->index = program->file_paths[program->get_random_fobj()];
            target->args[1]->value = mode_options[rand32(0, mode.max + 1)];
            return 0;
        }
};

class FtruncateMutator : public SyscallMutator {
    // int ftruncate(int fd, off_t length);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } length;

    public:
        FtruncateMutator(Program *program, Syscall *syscall = NULL) 
            : SyscallMutator(program, syscall) {
                length.max = PAGE_SIZE * 2;
                length.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->active_file_fds.empty())
                return NULL;

            Syscall *ret = new Syscall(SYS_ftruncate);
            ret->add_arg(new Arg(program->get_random_file_fd(), 1));	
            ret->add_arg(new Arg(rand32(0, length.max + 1), 0));

            program->add_syscall(ret);
            return ret;
        }
        uint32_t havoc(void) {
            target->args[1]->value = rand32(0, length.max + 1);
            return 0;
        }
};

class TruncateMutator : public SyscallMutator {
    // int truncate(const char *path, off_t length);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } length;

    public:
        TruncateMutator(Program *program, Syscall *syscall = NULL) 
            : SyscallMutator(program, syscall) {
                length.max = PAGE_SIZE * 2;
                length.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_truncate);
            FileObject *fobj = program->get_random_fobj();

            ret->add_arg(new Arg(program->file_paths[fobj], 1));	
            ret->add_arg(new Arg(rand32(0, length.max + 1), 0));

            program->add_syscall(ret);
            return ret;
        }
        uint32_t havoc(void) {
            target->args[1]->value = rand32(0, length.max + 1);
            return 0;
        }
};

class FstatMutator : public SyscallMutator {
    // int fstat(int fd, struct stat *buf);
    private:
        struct {
            uint64_t max;
            uint64_t cur;
        } fd;

    public: 
        FstatMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                fd.max = program->active_fds.size() - 1;
                fd.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->active_fds.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_fstat);

            ret->add_arg(new Arg(program->get_random_fd(), 1));
            ret->add_arg(new Arg(Program::dest8192, 1));

            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->active_fds.empty())
				return 0;
            target->args[0]->index = program->get_random_fd();
            return 0;
        }
};

class StatfsMutator : public SyscallMutator {
    // int statfs(const char *path, struct statfs *buf);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } path;

    public:
        StatfsMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
            }

        virtual Syscall* createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_statfs);
            ret->add_arg(new Arg(program->file_paths[program->get_random_fobj()], 1));
            ret->add_arg(new Arg(Program::dest8192, 1));
            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->avail_files.empty())
				return 0;
            target->args[0]->index = program->file_paths[program->get_random_fobj()];
            return 0;
        }
};

class FstatfsMutator : public SyscallMutator {
    // int fstatfs(int fd, struct statfs *buf);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } fd;

    public:
        FstatfsMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                fd.max = program->active_fds.size() - 1;
                fd.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->active_fds.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_fstatfs);
            ret->add_arg(new Arg(program->get_random_fd(), 1));
            ret->add_arg(new Arg(Program::dest8192, 1));
            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->active_fds.empty())
				return 0;
            target->args[0]->index = program->get_random_fd();
            return 0;
        }
};

class UtimesMutator : public SyscallMutator {
    // int utimes(const char *file, struct timeval tvp[2]);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } path;

    public: 
        UtimesMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_utimes);
            ret->add_arg(new Arg(program->file_paths[program->get_random_fobj()], 1));
            ret->add_arg(new Arg(Program::dest8192, 1));
            program->add_syscall(ret);
            return ret;
        }

        uint32_t havoc(void) {
			if (program->avail_files.empty())
				return 0;
            target->args[1]->index = program->file_paths[program->get_random_fobj()];
            return 0;
        }
};

class ReadlinkMutator : public SyscallMutator {
    // ssize_t readlink(const char *path, char *buf, size_t bufsiz);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } path;
    public:
        ReadlinkMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                path.max = program->avail_files.size() - 1;
                path.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_readlink);
            FileObject *fobj = program->get_random_fobj();
            ret->add_arg(new Arg(program->file_paths[fobj], 1));
            ret->add_arg(new Arg(Program::dest8192, 1));
            ret->add_arg(new Arg(PAGE_SIZE * 2, 0));
            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
			if (program->avail_files.empty())
				return 0;
            target->args[0]->index = program->file_paths[program->get_random_fobj()];
            return 0;
        }
};

class ChmodMutator : public SyscallMutator {
    // int chmod(const char *path, mode_t mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } mode;

        static const constexpr uint32_t mode_options[12] = 
        {S_ISUID, S_ISGID, S_ISVTX, S_IRUSR,
            S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, 
            S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH};

        int get_mode(uint32_t selector) {
            int ret = 0;
            uint8_t byte;
            for (int i = 0; i < 12; i++) {
                ret = ret | mode_options[selector & 1];
                selector >>= 1;
            }
            return ret;
        }

    public:
        ChmodMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                mode.max = (1 << 12) - 1;
                mode.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_chmod);
            FileObject *fobj = program->get_random_fobj();
            ret->add_arg(new Arg(program->file_paths[fobj], 1));

            ret->add_arg(new Arg(get_mode(rand32(0, mode.max + 1)), 0));
            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
            target->args[1]->value = get_mode(rand32(0, mode.max + 1));
            return 0;
        }
};

class FchmodMutator : public SyscallMutator {
    // int fchmod(int fd, mode_t mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } mode;

        static const constexpr uint32_t mode_options[12] = 
        {S_ISUID, S_ISGID, S_ISVTX, S_IRUSR,
            S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, 
            S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH};

        int get_mode(uint32_t selector) {
            int ret = 0;
            uint8_t byte;
            for (int i = 0; i < 12; i++) {
                ret = ret | mode_options[selector & 1];
                selector >>= 1;
            }
            return ret;
        }

    public:
        FchmodMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                mode.max = (1 << 12) - 1;
                mode.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->active_fds.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_fchmod);
            ret->add_arg(new Arg(program->get_random_fd(), 1));
            ret->add_arg(new Arg(get_mode(rand32(0, mode.max + 1)), 0));
            program->add_syscall(ret);
            return ret;
        }


        uint32_t havoc(void) {
            target->args[1]->value = get_mode(rand32(0, mode.max + 1));
            return 0;
        }
};

class FallocateMutator : public SyscallMutator {
	// int fallocate(int fd, int mode, off_t offset, off_t len);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } mode;

		struct {
			uint32_t max;
			uint32_t cur;
		} offset;

		struct {
			uint32_t max;
			uint32_t cur;
		} len;

        static const constexpr uint32_t mode_options[6] = 
		{ FALLOC_FL_KEEP_SIZE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_PUNCH_HOLE,
			FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_ZERO_RANGE,
			FALLOC_FL_INSERT_RANGE };

        int get_mode(uint32_t selector) {
            int ret = 0;
            uint8_t byte;
            for (int i = 0; i < 6; i++) {
                ret = ret | mode_options[selector & 1];
                selector >>= 1;
            }
            return ret;
        }

    public:
        FallocateMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                mode.max = (1 << 6) - 1;
                mode.cur = 0;
				offset.max = PAGE_SIZE * 2;
				offset.cur = 0;
				len.max = PAGE_SIZE * 2;
				len.cur = 0;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->active_file_fds.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_fallocate);
            ret->add_arg(new Arg(program->get_random_file_fd(), 1));
            ret->add_arg(new Arg(get_mode(rand32(0, mode.max + 1)), 0));
			ret->add_arg(new Arg(rand32(0, offset.max + 1), 0));
			ret->add_arg(new Arg(rand32(0, len.max + 1), 0));
            program->add_syscall(ret);

            return ret;
        }

		uint32_t havoc(void) {
			target->args[1]->value = get_mode(rand32(0, mode.max + 1));
			target->args[2]->value = rand32(0, offset.max + 1);
			target->args[3]->value = rand32(0, len.max + 1);
			return 0;	
		}
};

class MmapMutator : public SyscallMutator {

    // void *mmap(void *addr, size_t length, int prot, int flags,
    //                   int fd, off_t offset);
    private:
        static const constexpr int32_t prot_options[4] = 
        { PROT_EXEC, PROT_READ, PROT_WRITE, PROT_NONE };
        static const constexpr int32_t flags_options[7] = 
        {   //MAP_SHARED,
            //MAP_SHARED_VALIDATE,
            MAP_PRIVATE,
            MAP_32BIT,
            //MAP_ANONYMOUS,
            MAP_DENYWRITE,
            //MAP_EXECUTABLE,
            //MAP_FILE,
            //MAP_FIXED,
            //MAP_FIXED_NOREPLACE
            //MAP_GROWSDOWN
            // MAP_HUGETLB
            MAP_LOCKED,
            MAP_NONBLOCK,
            MAP_POPULATE
//            MAP_UNINITIALIZED
        };

        uint64_t __pick_prot() {
            uint32_t rp = rand32(0,4);
            uint32_t ret = 0;
            for(uint32_t i = 0; i < rp; i++) {
                ret |= prot_options[rand32(0,4)];
            }
        }
        uint64_t __pick_flags() {
            uint32_t rp = rand32(0,7);
            uint32_t ret = 0;
            for(uint32_t i = 0; i < rp; i++) {
                ret |= flags_options[rand32(0,7)];
            }
        }
    public:

        MmapMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
            }
        virtual ~MmapMutator() {}

        virtual Syscall* createTarget(const ArgMap& argMap) {
            if (program->active_file_fds.empty()) {
                return NULL;
            }

            Syscall* ret = new Syscall(SYS_mmap);
            int64_t fd_index;
            int64_t map_index;

            auto it = argMap.find(0);
            if (it == argMap.end())
                fd_index = program->get_random_file_fd();
            else
                fd_index = it->second;

            ret->add_arg(new Arg(0, 0));
            ret->add_arg(new Arg(rand32(1, 64 * PAGE_SIZE),0)); //len
            ret->add_arg(new Arg(__pick_prot(), 0));
            ret->add_arg(new Arg(__pick_flags(), 0));
            ret->add_arg(new Arg(fd_index, 1));
            ret->add_arg(new Arg(rand32(1,PAGE_SIZE >> 2),0));

            program->add_syscall(ret);
            
            map_index = program->create_variable(LONG, 0, NULL, MMAP_BASE);

            ret->ret_index = map_index;

            program->active_map_base_idx.push_back(map_index);

            return ret;
        }

  
        uint32_t havoc(void) {
            //assert(0 && "unimplemented!");
            target->args[1]->value = rand32(1,PAGE_SIZE*64); // len
            target->args[2]->value = __pick_prot();
            target->args[3]->value = __pick_flags();
            target->args[5]->value = rand32(0,PAGE_SIZE >> 2); //offset
            return 0;
        }
};

class MunmapMutator : public SyscallMutator {

    //int munmap(void *addr, size_t length);
    private:
    public:

        MunmapMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
            }
        virtual ~MunmapMutator() {}

        virtual Syscall* createTarget(const ArgMap& argMap) {
            if (program->active_map_base_idx.empty()) {
                // XXX: caller should gracefully handle return NULL
                // Caller at MutationStage.cpp 
                return NULL;
            }

            Syscall* ret = new Syscall(SYS_munmap);
            int64_t map_index;
            
            auto it = argMap.find(0);
            if (it == argMap.end()){
                size_t num_active_bases =
                    program->active_map_base_idx.size();
                map_index = 
                    program->active_map_base_idx[rand32(0,num_active_bases)];


            }
            else {
                map_index = it->second;
            }

            ret->add_arg(new Arg(map_index, 1)); //1 means variable.......
            ret->add_arg(new Arg(rand32(1, 64 * PAGE_SIZE),0)); // Random size should be OK?

            program->add_syscall(ret);
            program->mark_base_unmapped(map_index);

            program->show();
            exit(1);
            return ret;
        }
  
        uint32_t havoc(void) {
            target->args[1]->value = rand32(1,PAGE_SIZE * 64); // len
            return 0;
        }
};

/*********************** 
  The syscalls under this line are not suggested to be mutated once added.
 **********************/

class OpenMutator : public SyscallMutator {
    //int open(const char *pathname, int flags, mode_t mode);
    private:
        struct {
            uint32_t max;
            uint32_t cur;
        } flag;
        struct {
            uint32_t max;
            uint32_t cur;
        } mode;

        FileObject *new_fobj;

    public:

        OpenMutator(Program* program, Syscall* syscall = NULL)
            : SyscallMutator(program, syscall) {
                this->flag.max = 0x2FF; ///usr/include/feature.h
                this->flag.cur = 0;
                this->mode.max = 0666;
                this->mode.cur = 0;
                new_fobj = NULL;
            }
        virtual ~OpenMutator() {}

        // special for open
        Syscall* createTarget(FileObject* fobj) {
            Syscall *syscall = new Syscall(SYS_open);
            
            if (fobj != NULL) {
                // arg1: path
                auto it = program->file_paths.find(fobj);
                assert(it != program->file_paths.end());
                syscall->add_arg(new Arg(it->second, 1));

                // arg2: flags (very simple now)
                int64_t flags;
                if (fobj->type == I_DIR)
                    flags = O_RDONLY | O_DIRECTORY;
                else
                    flags = O_RDWR;
                syscall->add_arg(new Arg(flags, 0));

                // arg3: mode
                int64_t mode = 0; // we open existing file
                syscall->add_arg(new Arg(mode, 0));

                // ret: fd
                int64_t fd_index = program->create_variable(LONG, 0, NULL, fobj->type);
                // printf("fd_index: %ld\n", fd_index);
                syscall->ret_index = fd_index;
                program->add_fd(fd_index);
            
            } else {

                std::string path = program->rand_path();
                int64_t path_index = 
                    program->create_variable(STRING, path.length() + 1, (uint8_t *)(path.c_str()));
                syscall->add_arg(new Arg(path_index, 1));

                int64_t flags = O_RDWR | O_CREAT; 
                syscall->add_arg(new Arg(flags, 0));

                int64_t mode = 0666;
                syscall->add_arg(new Arg(mode, 0));

                int64_t fd_index = program->create_variable(LONG, 0, NULL, I_FILE);
                syscall->ret_index = fd_index;
                program->add_fd(fd_index);

                // side effects
                new_fobj = new FileObject(I_FILE);
                program->add_file(new_fobj);
                program->file_paths.insert(std::make_pair(new_fobj, path_index));
                
            }

            program->add_syscall(syscall);
            return syscall;
        }

        virtual Syscall* createTarget(const ArgMap &argMap) {
            if (program->avail_files.empty())
                return createTarget(NULL);
            else
                return createTarget(rand32(0, 2) ? NULL : program->get_random_fobj());
        }

        virtual void releaseTarget() {
            program->remove_last_variable();
            if (new_fobj != NULL) { // we create a variable and a file for path
                program->remove_last_variable();
                program->remove_file(new_fobj);
                program->file_paths.erase(new_fobj);
            }
            SyscallMutator::releaseTarget();
        }
};

class RenameMutator : public SyscallMutator {
    // int rename(const char *old, const char *new);
    private:
        FileObject *fobj;
        bool create_new_path;

    public:

        RenameMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.size() < 2)
				return NULL;

            Syscall *ret = new Syscall(SYS_rename);
            int64_t path_index;
            do {
                fobj = program->get_random_fobj();
                path_index = program->file_paths[fobj];
            } while (path_index == program->root_path_index);
            ret->add_arg(new Arg(path_index, 1));

            int64_t new_path_index;
            // arg2: new
            switch(rand32(0, 4)) {

                // set new file name as an existing name
                case 0 ... 1: {

                    do { 
                        FileObject *other = program->get_random_fobj();
                        new_path_index = program->file_paths[other];
                    } while (new_path_index == program->root_path_index);
                    ret->add_arg(new Arg(new_path_index, 1));
                    create_new_path = false;
                    break;
                }

                // random generate a string as new file name; 
                // TODO: generate random path?
                case 2 ... 3: {

                    std::string new_path = program->rand_path();
                    new_path_index = program->create_variable(	
                            STRING, new_path.length() + 1, 
                            (uint8_t *)(new_path.c_str()));
                    ret->add_arg(new Arg(new_path_index, 1));
                    create_new_path = true;
                    break;
                 }

                 default:
                     assert(0);

            }

            program->add_syscall(ret);
            program->file_paths[fobj] = new_path_index;

            return ret;
        }

        virtual void releaseTarget() {
            if (create_new_path) {
                program->remove_last_variable();
            }
            program->file_paths[fobj] = original->args[0]->index;
            SyscallMutator::releaseTarget();
        }
};

class MkdirMutator : public SyscallMutator {
    private:
        FileObject *new_dir;

    public:
        MkdirMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                new_dir = NULL;
            }	

        virtual Syscall *createTarget(const ArgMap &argMap) {
            Syscall *ret = new Syscall(SYS_mkdir);

            std::string path = program->rand_path();
            int64_t path_index = 
                program->create_variable(STRING, path.length() + 1, (uint8_t *)(path.c_str()));
            ret->add_arg(new Arg(path_index, 1));

            program->add_syscall(ret);
            new_dir = new FileObject(I_DIR);
            program->add_file(new_dir);
            program->file_paths.insert(std::make_pair(new_dir, path_index));

            return ret;
        }

        virtual void releaseTarget() {
            program->remove_last_variable();
            program->remove_file(new_dir);
            program->file_paths.erase(new_dir);
            SyscallMutator::releaseTarget();
        }
};

class RmdirMutator : public SyscallMutator {
    // int rmdir(const char *path);
    private:
        FileObject *removed_dir;

    public:
        RmdirMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_dirs.size() == 1)
				return NULL;

            Syscall *ret = new Syscall(SYS_rmdir);
            int64_t path_index;
            do {
                removed_dir = program->get_random_dir();	
                path_index = program->file_paths[removed_dir];
            } while (path_index == program->root_path_index);
            ret->add_arg(new Arg(path_index, 1));

            program->add_syscall(ret);
            
            // side effects
            program->file_paths.erase(removed_dir);
            program->remove_file(removed_dir);
            return ret;
        }

        virtual void releaseTarget() {
            program->add_file(removed_dir);
            program->file_paths[removed_dir] = original->args[0]->index;
            SyscallMutator::releaseTarget();
        }
};

class LinkMutator : public SyscallMutator {
    // int link(const char *oldpath, const char *newpath);
    private:
        FileObject *new_copy;

    public:
        LinkMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_link);
            FileObject *fobj = program->get_random_fobj();
            ret->add_arg(new Arg(program->file_paths[fobj], 1));	

            std::string path = program->rand_path();
            int64_t path_index = 
                program->create_variable(STRING, path.length() + 1, (uint8_t *)(path.c_str()));
            ret->add_arg(new Arg(path_index, 1));

            // side effects
            new_copy = new FileObject(*fobj);
            program->add_file(new_copy);
            program->file_paths.insert(std::make_pair(new_copy, path_index));

            program->add_syscall(ret);
            return ret;
        }

        // remove side effects
        virtual void releaseTarget() {
            program->remove_last_variable();
            program->remove_file(new_copy);
            program->file_paths.erase(new_copy);
            SyscallMutator::releaseTarget();
        }
};

class UnlinkMutator : public SyscallMutator {
    // int unlink(const char *pathname);
    private:
        FileObject *removed_file;

    public:
        UnlinkMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_non_dirs.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_unlink);
            removed_file = program->get_random_file();
            ret->add_arg(new Arg(program->file_paths[removed_file], 1));

            program->add_syscall(ret);

            program->file_paths.erase(removed_file);
            program->remove_file(removed_file);
            return ret;
        }

        virtual void releaseTarget() {
            program->add_file(removed_file);
            program->file_paths[removed_file] = original->args[0]->index;
            SyscallMutator::releaseTarget();
        }
};

class SymlinkMutator : public SyscallMutator {
    // int symlink(const char *target, const char *linkpath);
    private:
        FileObject *link;

    public:
        SymlinkMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
            Syscall *ret = new Syscall(SYS_symlink);
            FileObject *fobj = program->get_random_fobj();
            ret->add_arg(new Arg(program->file_paths[fobj], 1));

            std::string path = program->rand_path();
            int64_t path_index = 
                program->create_variable(STRING, path.length() + 1, (uint8_t *)(path.c_str()));
            ret->add_arg(new Arg(path_index, 1));

            // side effects
            link = new FileObject(I_SYMLINK);
            program->add_file(link);
            program->file_paths.insert(std::make_pair(link, path_index));

            program->add_syscall(ret);
            return ret;				
        }

        virtual void releaseTarget() {
            program->remove_last_variable();
            program->remove_file(link);
            program->file_paths.erase(link);
            SyscallMutator::releaseTarget();
        }
}; 

class SetxattrMutator : public SyscallMutator {
    // int setxattr(const char *path, const char *name,
    // 				const void *value, size_t size, int flags);
    private:
        FileObject *target_fobj;
        BufferObject *new_name;
        bool xattr_create;

    public:
        SetxattrMutator(Program *program, Syscall *syscall = NULL)
            : SyscallMutator(program, syscall) {
                xattr_create = false;
                target_fobj = NULL;
            }

        virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

            Syscall *ret = new Syscall(SYS_setxattr);
            target_fobj = program->get_random_fobj();
            ret->add_arg(new Arg(program->file_paths[target_fobj], 1));	

            uint32_t value_len = rand32(1, 128 + 1);
            uint8_t *value = random_buffer(value_len);
            int64_t value_index = program->create_variable(PUCHAR, 
                    value_len, value);

            std::string random_name;
            uint32_t name_len;
            uint8_t *name;
            int flags = -1;
            int64_t name_index = -1;

            if (target_fobj->xattrs.size() != 0) {
                if (rand32(0, 2) == 0) {
                    // replace
                    flags = XATTR_REPLACE;	
                    BufferObject *name = target_fobj->get_random_xattr(); 
                    name_index = program->create_variable(STRING, name->size, name->buffer);
                    xattr_create = false;
                    goto out;
                }
            }

            flags = XATTR_CREATE;
            random_name = random_xattr_name();
            name_len = random_name.length() + 1;
            name = (uint8_t *)malloc(name_len);
            memcpy(name, random_name.c_str(), name_len);
            name_index = program->create_variable(STRING, name_len, name);
            xattr_create = true;

            // side effects
            new_name = new BufferObject(name, name_len);
            target_fobj->add_xattr(new_name);

out:
            ret->add_arg(new Arg(name_index, 1));
            ret->add_arg(new Arg(value_index, 1));	
            ret->add_arg(new Arg(value_len, 0));
            ret->add_arg(new Arg(flags, 0));

            program->add_syscall(ret);
            return ret;
        }

        virtual void releaseTarget() {
            // totally two variables created
            program->remove_last_variable();
            program->remove_last_variable();
            if (xattr_create)
                target_fobj->remove_xattr(new_name);
            SyscallMutator::releaseTarget();
        }
};

class ListxattrMutator : public SyscallMutator {
	// ssize_t listxattr(const char *path, char *list, size_t size);

	public:
		ListxattrMutator(Program *program, Syscall *syscall = NULL)
			: SyscallMutator(program, syscall) {
				;
			}

		virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;
			
			Syscall *ret = new Syscall(SYS_listxattr);	
			FileObject *fobj = program->get_random_fobj();
			ret->add_arg(new Arg(program->file_paths[fobj], 1));
			ret->add_arg(new Arg(Program::dest8192, 1));
			ret->add_arg(new Arg(rand32(0, PAGE_SIZE * 2), 0));
							
			program->add_syscall(ret);
			return ret;
		}
};

class RemovexattrMutator : public SyscallMutator {
	// int removexattr(const char *path, const char *name);
	private:
		FileObject *target_fobj;
		BufferObject *old_xattr_name;

	public:
		RemovexattrMutator(Program *program, Syscall *syscall = NULL)
			: SyscallMutator(program, syscall) {
				target_fobj = NULL;
				old_xattr_name = NULL;
			}

		virtual Syscall *createTarget(const ArgMap &argMap) {
			if (program->avail_files.empty())
				return NULL;

			Syscall *ret = new Syscall(SYS_removexattr);
			target_fobj = program->get_random_fobj();
			ret->add_arg(new Arg(program->file_paths[target_fobj], 1));
			
			int64_t name_index = -1;
			if (target_fobj->xattrs.size() != 0) {
				old_xattr_name = target_fobj->get_random_xattr();
				name_index = program->create_variable(STRING, old_xattr_name->size, old_xattr_name->buffer);
				// side effects
                target_fobj->remove_xattr(old_xattr_name);
			} else {
				std::string random_name = random_xattr_name();
				uint32_t name_len = random_name.length() + 1;
				uint8_t *name = (uint8_t *)malloc(name_len);
				memcpy(name, random_name.c_str(), name_len);
				name_index = program->create_variable(STRING, name_len, name);
			}

			ret->add_arg(new Arg(name_index, 1));
			program->add_syscall(ret);	
			return ret;
		}

		virtual void releaseTarget() {
			program->remove_last_variable();
			if (old_xattr_name)
				target_fobj->add_xattr(old_xattr_name);
			SyscallMutator::releaseTarget();
		}

};

