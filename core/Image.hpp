#ifndef _IMAGE_HPP
#define _IMAGE_HPP

#include <string.h>

#include <vector>
#include <string>
#include <algorithm>

#include "Utils.hpp"

#define I_FILE 	 0x01
#define I_DIR 	 0x02
#define I_SYMLINK  0x03
#define I_FIFO	 0x04

struct FileObject
{
	std::string rel_path;
	uint8_t type;

	std::vector<BufferObject*> xattrs;

	FileObject() {}
	FileObject(uint8_t type) : type(type) {}
	FileObject(const FileObject &other) {
		type = other.type;
		for (BufferObject* other_name : other.xattrs) {
			size_t name_len = other_name->size;
			uint8_t *name = (uint8_t *)malloc(name_len);
			memcpy(name, other_name->buffer, name_len);
			xattrs.push_back(new BufferObject(name, name_len));
		}
	}

	BufferObject* get_random_xattr() {
		return xattrs[rand32(0, xattrs.size())];
	}

	void add_xattr(uint8_t *buffer, uint32_t size) {
		xattrs.push_back(new BufferObject(buffer, size));
	}

	void add_xattr(BufferObject *name) {
		xattrs.push_back(name);
	}

    void remove_xattr(BufferObject *name) {
        xattrs.erase(std::remove(xattrs.begin(), xattrs.end(), name), xattrs.end());
    }

	void remove_last_xattr() {
		BufferObject *name = xattrs.back();
		xattrs.pop_back();
		delete name;
	}

	~FileObject() 
	{
		BufferObject *name;
		for (std::vector<BufferObject*>::iterator it = xattrs.begin();
				it != xattrs.end(); it++) {
			name = *it;
			delete name;
		}
		xattrs.clear();
	}

	void show(const char *path = NULL);
};

struct Image
{
	std::vector<FileObject*> file_objs;

	~Image();

	static Image* deserialize(const char *path);
	void show();
};

#endif
