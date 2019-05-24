#ifndef _UTILS_HPP
#define _UTILS_HPP

#include <stdint.h>
#include <stdlib.h>

struct BufferObject
{
	uint8_t *buffer;
	uint32_t size;

	BufferObject() {}
	BufferObject(uint8_t *buffer, uint32_t size) : 
		buffer(buffer), size(size) {
		;
	}

	~BufferObject() {
		if (buffer)
			free(buffer);
	}
};

bool copyfile(const char *src_path, const char *dst_path);
void print_binstr(const uint8_t *buffer, uint32_t size);
uint32_t rand32(uint32_t start, uint32_t end);
std::string random_string(size_t length);
uint8_t* random_buffer(uint32_t length);
std::string random_xattr_name(void);

// void rand_init();


#endif
