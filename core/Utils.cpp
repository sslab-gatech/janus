#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include <random>
#include <string>
#include <algorithm>

#include "Utils.hpp"
#include "Constants.hpp"

static std::mt19937 *rng;

bool copyfile(const char *src_path, const char *dst_path) {
	struct stat st;
	lstat(src_path, &st);

	int r_fd = open(src_path, O_RDONLY);
	int w_fd = open(dst_path, O_CREAT | O_RDWR | O_TRUNC, 0666);

	if (sendfile(w_fd, r_fd, NULL, st.st_size) == st.st_size)
		return true;
	else
		return false;
}

void print_binstr(const uint8_t *buffer, uint32_t size) {
	for (uint32_t i = 0; i < size; i++) {
	    printf("\\x%02x", buffer[i]);
	}
}

// return [start, end)
uint32_t rand32(uint32_t start, uint32_t end) {
	return start + rand() % (end - start);
}

// random string
std::string random_string(size_t length)
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

// random xattr name
std::string random_xattr_name() {
	if (rand32(0, 2)) {
		return std::string(default_xattr[rand32(0, NUM_DEFAULT_XATTR)]);
	} else {
		std::string base = default_xattr_prefix[rand32(0, NUM_DEFAULT_XATTR_PREFIX)];
		return base + random_string(8);
	}
}

// random buffer
uint8_t* random_buffer(uint32_t length)
{
	uint8_t *ret = (uint8_t *)malloc(length);
	for (uint32_t i = 0; i < length; i++)
		ret[i] = rand() % 0xff;
	return ret;
}

// random by mt19937
void rand_init() {
  rng = new std::mt19937(); 
  rng->seed(std::random_device()());
}

/*
uint32_t rand32(uint32_t start, uint32_t end) {
    std::uniform_int_distribution<std::mt19937::result_type> dist(start, end - 1);
    return dist(*rng);
}
*/
