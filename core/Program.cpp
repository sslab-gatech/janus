#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <iostream>


#include "Program.hpp"
#include "Image.hpp"
#include "Constants.hpp"

/* 
format:
[ variable_num ]	[ name | type | size | has_value | value ] 
[ syscall_num ]
	[ syscall_nr | syscall_arg1_is_var | syscall_arg1 | ... | syscall_ret_index ]
[ fileobjs_num ]
	[ path_variable_index
	| type
	| xattr_num 
		[ name_len | name | value_len | value ]
	]
*/

/******************** constructor **********************/
Program::Program() : variable_cnt(0)
    //active_map_base_idx(variable_indices[10])
{
    //variable_indices.resize(variable_list::SIZE);
}

/******************** show **********************/
void show_variable(Variable *v)
{
	if (v->type == LONG) 
		printf("\tlong %s;\n", v->name.c_str());
	else if (v->type == STRING)
		printf("\tchar %s[] = \"%s\";\n", v->name.c_str(), (char *)v->value);		
	else if (v->type == PUCHAR) {
		printf("\tunsigned char %s[%d];\n", v->name.c_str(), v->size);
		if (v->value != 0) {
			printf("\tmemcpy(%s, \"", v->name.c_str());
			print_binstr((uint8_t *)(v->value), v->size);
			printf("\", %d);\n", v->size);
		}
	} else
		assert(0);
}

void show_syscall(Program *prog, Syscall *syscall)
{
	if (syscall->ret_index != -1) {
		printf("\t%s = syscall(%s", (prog->variables[syscall->ret_index])->name.c_str(), syscall_name[syscall->nr]);
	}
	else
		printf("\tsyscall(%s", syscall_name[syscall->nr]);
	for (Arg *arg : syscall->args) {
		if (arg->is_variable) 
			printf(", (long)%s", (prog->variables[arg->index])->name.c_str());
		else
			printf(", %ld", arg->value);
	}
	printf(");\n");
}

static void show_headers()
{
	printf("#include <sys/types.h>\n\
#include <sys/mount.h>\n\
#include <sys/mman.h>\n\
#include <sys/stat.h>\n\
#include <sys/xattr.h>\n\
#include <sys/syscall.h>\n\n\
#include <dirent.h>\n\
#include <errno.h>\n\
#include <error.h>\n\
#include <fcntl.h>\n\
#include <stdio.h>\n\
#include <stdlib.h>\n\
#include <string.h>\n\
#include <unistd.h>\n");
}

void Program::show() 
{
	show_headers();
	printf("\nint main(int argc, char *argv[])\n{\n");

	for (Variable *v : variables)
		show_variable(v);

	for (Syscall *syscall : syscalls)
		show_syscall(this, syscall);

    printf("\n");
    for (int64_t fd_index : active_fds)
        printf("\tclose(%s);\n", variables[fd_index]->name.c_str());

    printf("\treturn 0;\n");
	printf("}\n");

	printf("/* Active fds: ");
	for (int64_t fd_index : active_fds)
		printf("%s ", variables[fd_index]->name.c_str());
	printf("*/\n");

	printf("/* Files\n");
	for (FileObject *fobj : avail_files) {
		fobj->show((const char *)variables[file_paths[fobj]]->value);
	}
	printf("*/\n");

}

/******************** varaibles **********************/
void Program::prepare_buffers()
{
	assert(create_variable(PUCHAR, PAGE_SIZE * 2) == Program::src8192);
	assert(create_variable(PUCHAR, PAGE_SIZE * 2) == Program::dest8192);
}

void Program::prepare_file_paths()
{
	for (FileObject *fobj : avail_files) {
		int64_t path_index = create_variable(STRING, fobj->rel_path.length() + 1, (uint8_t *)(fobj->rel_path.c_str()));
		file_paths.insert(std::make_pair(fobj, path_index));
	}
}

int64_t Program::create_variable(uint8_t type, uint32_t size, uint8_t *value, uint8_t kind)
{
	Variable *v = new Variable;
	v->type = type;
	v->size = size;

	if (value == NULL)
		v->value = 0;
	else {
		v->value = (uint8_t*)malloc(size);
		memcpy((void *)(v->value), value, size);
	}

	v->kind = kind;
	v->name = "v" + std::to_string(variable_cnt);
    add_variable(v);
	return variable_cnt - 1;
}

static inline void _readmem(void *dest, void *src, uint32_t *ppos, uint32_t len) {
	uint32_t pos = *ppos;
	memcpy(dest, (char *)src + pos, len);
	*ppos = pos + len;
}

static inline void _writemem(void *dest, void *src, uint32_t *ppos, uint32_t len) {
	uint32_t pos = *ppos;
	memcpy((char *)dest + pos, src, len);
	*ppos = pos + len;
}

/******************** (de-)serializer **********************/
Program *Program::deserialize(uint8_t *buf, uint32_t len)
{
	uint32_t pos = 0;
	Program *program = new Program;

	// variables
	uint32_t variable_num;
	_readmem(&variable_num, buf, &pos, sizeof(uint32_t));
	program->variables.reserve(variable_num);

	for (uint32_t i = 0; i < variable_num; i++) {
		Variable *v = new Variable;
		v->name = "v" + std::to_string(i);
		_readmem(&(v->type), buf, &pos, sizeof(uint8_t));
		if (v->is_pointer()) {
			_readmem(&(v->size), buf, &pos, sizeof(uint32_t));
			uint8_t has_value;
			_readmem(&has_value, buf, &pos, sizeof(uint8_t));
			if (has_value) {
				v->value = (uint8_t*)malloc(v->size);
				_readmem(v->value, buf, &pos, v->size);
			}
		}
		_readmem(&(v->kind), buf, &pos, sizeof(uint8_t));    
		program->add_variable(v);
	}

	// syscalls
	uint32_t syscall_num;
	_readmem(&syscall_num, buf, &pos, sizeof(uint32_t));
	program->syscalls.reserve(syscall_num);

	for (uint32_t i = 0; i < syscall_num; i++) {
		uint32_t syscall_nr;
		_readmem(&syscall_nr, buf, &pos, sizeof(int32_t));
		Syscall *syscall = new Syscall(syscall_nr);

		uint32_t arg_num;
		_readmem(&arg_num, buf, &pos, sizeof(uint32_t));
		syscall->args.reserve(arg_num);

		for (uint32_t j = 0; j < arg_num; j++) {
			Arg *arg = new Arg;
			_readmem(&(arg->is_variable), buf, &pos, sizeof(uint8_t));
			if (arg->is_variable)
				_readmem(&(arg->index), buf, &pos, sizeof(int64_t));
			else
				_readmem(&(arg->value), buf, &pos, sizeof(int64_t));
			syscall->args.push_back(arg);
		}

		_readmem(&(syscall->ret_index), buf, &pos, sizeof(int64_t));
		program->syscalls.push_back(syscall);
	}

	// files
	uint32_t fileObjNum;
	_readmem(&fileObjNum, buf, &pos, sizeof(uint32_t));
	program->avail_files.reserve(fileObjNum);
	for (uint32_t i = 0; i < fileObjNum; i++) {
		FileObject *fobj = new FileObject;

		int64_t path_index;
		_readmem(&path_index, buf, &pos, sizeof(int64_t));
		program->file_paths.insert(std::make_pair(fobj, path_index));
        if (!strcmp((char *)(program->variables[path_index]->value), "."))
            program->root_path_index = path_index;

		_readmem(&(fobj->type), buf, &pos, sizeof(uint8_t));

		uint32_t xattr_num = 0;
		_readmem(&xattr_num, buf, &pos, sizeof(uint32_t));
		for (uint32_t j = 0; j < xattr_num; j++) {
			uint8_t *name_buf;
			uint32_t name_len;

			_readmem(&name_len, buf, &pos, sizeof(uint32_t));
			name_buf = (uint8_t *)malloc(name_len);
			if (name_buf == NULL)
				goto exit;
			_readmem(name_buf, buf, &pos, name_len);

			fobj->xattrs.push_back(new BufferObject(name_buf, name_len));
		}

		program->add_file(fobj);	
	}

	assert(pos == len);
	return program;

exit:
	delete program;
	return NULL;
}

Program *Program::deserialize(const char *path, bool for_execution) 
{
	int fd = open(path, O_RDONLY);
	if (fd <= 0) {
       	assert(0 && "failed to open file to deserialize");
		return NULL;
    }

	Program *program = new Program;

	// variables
	uint32_t variable_num;
	read(fd, &variable_num, sizeof(uint32_t));
	program->variables.reserve(variable_num);

	for (uint32_t i = 0; i < variable_num; i++) {
		Variable *v = new Variable;
		v->name = "v" + std::to_string(i);
		read(fd, &(v->type), sizeof(uint8_t));
		if (v->is_pointer()) {
			read(fd, &(v->size), sizeof(uint32_t));
			uint8_t has_value;
			read(fd, &has_value, sizeof(uint8_t));
			if (has_value) {
				v->value = (uint8_t*)malloc(v->size);
				read(fd, (void *)(v->value), v->size);
			}
		}
		read(fd, &(v->kind), sizeof(uint8_t));
		program->add_variable(v);
	}

	// syscalls
	uint32_t syscall_num;
	read(fd, &syscall_num, sizeof(uint32_t));
	program->syscalls.reserve(syscall_num);

	for (uint32_t i = 0; i < syscall_num; i++) {
		uint32_t syscall_nr;	
		read(fd, &syscall_nr, sizeof(int32_t));
		Syscall *syscall = new Syscall(syscall_nr);

		uint32_t arg_num;
		read(fd, &arg_num, sizeof(uint32_t));
		syscall->args.reserve(arg_num);

		for (uint32_t j = 0; j < arg_num; j++) {
			Arg *arg = new Arg;
			read(fd, &(arg->is_variable), sizeof(uint8_t));
			if (arg->is_variable)
				read(fd, &(arg->index), sizeof(int64_t));
			else
				read(fd, &(arg->value), sizeof(int64_t));
			syscall->args.push_back(arg);
		}
		
		read(fd, &(syscall->ret_index), sizeof(int64_t));
		
		program->syscalls.push_back(syscall);
	}
		
	if (!for_execution) {
		// files
		uint32_t fileObjNum = 0;
		read(fd, &fileObjNum, sizeof(uint32_t));

		for (uint32_t i = 0; i < fileObjNum; i++) {

			FileObject *fobj = new FileObject;
			int64_t path_index;
			read(fd, &path_index, sizeof(int64_t));
			program->file_paths.insert(std::make_pair(fobj, path_index));
            if (!strcmp((char *)(program->variables[path_index]->value), "."))
                program->root_path_index = path_index;

			read(fd, &(fobj->type), sizeof(uint8_t));

			uint32_t xattr_num = 0;
			read(fd, &xattr_num, sizeof(uint32_t));

			for (uint32_t j = 0; j < xattr_num; j++) {

				uint8_t *name_buf;
				uint32_t name_len;

				read(fd, &name_len, sizeof(uint32_t));
				name_buf = (uint8_t *)malloc(name_len);
				if (name_buf == NULL)
					goto exit;
				read(fd, name_buf, name_len);

				fobj->xattrs.push_back(new BufferObject(name_buf, name_len));
			}
			program->add_file(fobj);
		}
	}

	close(fd);
	return program;

exit:
	close(fd);
	delete program;
	return NULL;
}

uint32_t Program::serialize(uint8_t *buf, uint32_t len)
{
	uint32_t pos = 0;

	// variables
	uint32_t variable_num = variables.size();
	_writemem(buf, &variable_num, &pos, sizeof(uint32_t));
	for (Variable *v : variables) {
		_writemem(buf, &(v->type), &pos, sizeof(uint8_t));
		if (v->is_pointer()) {
			_writemem(buf, &(v->size), &pos, sizeof(uint32_t));
			uint8_t has_value = v->value == 0 ? 0 : 1;
			_writemem(buf, &has_value, &pos, sizeof(uint8_t));
			if (has_value)
				_writemem(buf, (void *)v->value, &pos, v->size);
		}
		_writemem(buf, &(v->kind), &pos, sizeof(uint8_t));
	}

	// syscalls
	uint32_t syscall_num = syscalls.size();
	_writemem(buf, &syscall_num, &pos, sizeof(uint32_t));
	for (Syscall *syscall : syscalls) {
		_writemem(buf, &(syscall->nr), &pos, sizeof(uint32_t));
		uint32_t arg_num = syscall->args.size();
		_writemem(buf, &arg_num, &pos, sizeof(uint32_t));
		for (Arg *arg : syscall->args) {
			_writemem(buf, &(arg->is_variable), &pos, sizeof(uint8_t));
			if (arg->is_variable)
				_writemem(buf, &(arg->index), &pos, sizeof(int64_t));
			else
				_writemem(buf, &(arg->value), &pos, sizeof(int64_t));
		}
		_writemem(buf, &(syscall->ret_index), &pos, sizeof(int64_t));
	}

	// files
	uint32_t fileObjNum = avail_files.size();
	_writemem(buf, &fileObjNum, &pos, sizeof(uint32_t));
	for (FileObject *fobj : avail_files) {
		auto it = file_paths.find(fobj);
		assert(it != file_paths.end());
		_writemem(buf, &(it->second), &pos, sizeof(int64_t));

		_writemem(buf, &(fobj->type), &pos, sizeof(uint8_t));

		uint32_t xattr_num = fobj->xattrs.size();
		_writemem(buf, &xattr_num, &pos, sizeof(uint32_t));

		for (BufferObject *name : fobj->xattrs) {
			_writemem(buf, &(name->size), &pos, sizeof(uint32_t));
			_writemem(buf, name->buffer, &pos, name->size);
		}
	}

    assert(pos < len);
	return pos;
}

bool Program::serialize(const char *path) 
{
	int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0666);

	// variables
	uint32_t variable_num = variables.size();
	write(fd, &variable_num, sizeof(uint32_t));

	for (Variable *v : variables) {
		write(fd, &(v->type), sizeof(uint8_t));
		if (v->is_pointer()) {
			write(fd, &(v->size), sizeof(uint32_t));
			uint8_t has_value = v->value == 0 ? 0 : 1;
			write(fd, &has_value, sizeof(uint8_t));
			if (has_value) {
				write(fd, (void *)v->value, v->size);
			}
		}
		write(fd, &(v->kind), sizeof(uint8_t));
	}

	// syscalls
	uint32_t syscall_num = syscalls.size();
	write(fd, &syscall_num, sizeof(uint32_t));
	for (Syscall *syscall : syscalls) {
		write(fd, &(syscall->nr), sizeof(int32_t));
		uint32_t arg_num = syscall->args.size();
		write(fd, &arg_num, sizeof(uint32_t));
		for (Arg *arg : syscall->args) {
			write(fd, &(arg->is_variable), sizeof(uint8_t));
			if (arg->is_variable)
				write(fd, &(arg->index), sizeof(int64_t));
			else
				write(fd, &(arg->value), sizeof(int64_t));	
		}
		write(fd, &(syscall->ret_index), sizeof(int64_t));
	}
	
	// files
	uint32_t fileObjNum = avail_files.size();
	write(fd, &fileObjNum, sizeof(uint32_t));

	for (FileObject *fobj : avail_files) {
		// uint32_t len = fobj->rel_path.length();
		// write(fd, &len, sizeof(uint32_t));
		// write(fd, fobj->rel_path.c_str(), len);
		auto it = file_paths.find(fobj);
		assert(it != file_paths.end());
		write(fd, &(it->second), sizeof(int64_t));

		write(fd, &(fobj->type), sizeof(uint8_t));

		uint32_t xattr_num = fobj->xattrs.size();
		write(fd, &xattr_num ,sizeof(uint32_t));

		for (BufferObject *name : fobj->xattrs) {
			write(fd, &(name->size), sizeof(uint32_t));
			write(fd, name->buffer, name->size);
		}
	}

	close(fd);
	return true;
}

/******************** path generator ******************/
std::string Program::rand_path()
{
	FileObject *fobj = get_random_dir();
    auto it = file_paths.find(fobj);
    assert(it != file_paths.end());
	int64_t path_index = it->second;
	std::string ret = std::string((char *)(variables[path_index]->value));
	ret += "/" + random_string(8);
	return ret;
}

/******************** destructor **********************/
Variable::~Variable() 
{
	if (is_pointer() && value)
		free((void *)value);
}

Syscall::~Syscall() 
{
	Arg *arg;
	for (std::vector<Arg*>::iterator it = args.begin();
		it != args.end(); it++) {
		arg = *it;
		delete arg;
	}
}

Program::~Program() 
{
	Variable *v;
	for (std::vector<Variable*>::iterator it = variables.begin();
		it != variables.end(); it++) {
		v = *it;
		delete v;
	}

	Syscall *f;
	for (std::vector<Syscall*>::iterator it = syscalls.begin();
		it != syscalls.end(); it++) {
		f = *it;
		delete f;
	}

	FileObject *fobj;
	for (std::vector<FileObject*>::iterator it = avail_files.begin();
		it != avail_files.end(); it++) {
		fobj = *it;
		delete fobj;
	}
}

