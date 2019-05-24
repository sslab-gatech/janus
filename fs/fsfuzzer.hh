#ifndef FS_FUZZ_FSFUZZER_HH
#define FS_FUZZ_FSFUZZER_HH

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include <set>
#include <vector>
#include <string>
#include <iostream>

#include "mount.hh"
#include "utils.hh"

class fsfuzzer {


  public:

    typedef std::pair<uint64_t, uint64_t> extent_t;

    fsfuzzer(const char *fstype): fstype_(fstype) {
      ;
    }

    ~fsfuzzer() {
      //if (image_path_)
      // free(image_path_);
      // if (image_buffer_)
      // munmap(image_buffer_, image_size_);
    }

    virtual void fix_checksum() {}

    virtual void fix_general_checksum() {}

    virtual void compress(const char *in_path, void *buffer, const char *meta_path = NULL) {}

    virtual void decompress(const void *meta_buffer, size_t meta_len, bool checksum = true) {}

    virtual void general_decompress(const void *meta_buffer, size_t meta_len, bool checksum = true) {}

    void general_compress(const char *in_path, void *buffer, const char *meta_path = NULL) {
        
        void *zero;
        struct stat st;
        bool generate_meta_image = meta_path != NULL;

        stat(in_path, &st);
        image_size_ = st.st_size;
        block_size_ = 64;
        block_count_ = image_size_ / block_size_;
        
        zero = malloc(block_size_);
        memset(zero, 0, sizeof(zero));
        
        int in_image_fd = open(in_path, O_RDONLY);
        if (in_image_fd < 0)
            FATAL("[-] image %s compression failed.", in_path);
        
        image_buffer_ = buffer;
        if (read(in_image_fd, image_buffer_, image_size_) != image_size_) {
            perror("compress");
            FATAL("[-] image %s compression failed.", in_path);
        }
        
        close(in_image_fd);

        std::set<uint64_t> meta_blocks;
        for (uint64_t i = 0; i < block_count_; i++) {
            if (memcmp((char *)image_buffer_ + i * block_size_, zero, block_size_))
                meta_blocks.insert(i);
        }

        int meta_image_fd = -1;
        if (generate_meta_image) {
            meta_image_fd = open(meta_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
            if (meta_image_fd < 0)
                FATAL("[-] image %s compression failed.", in_path);
        }

        if (!release_metadata(meta_blocks, meta_image_fd, true))
            FATAL("[-] image %s compression failed.", in_path);
        
        if (generate_meta_image)
            close(meta_image_fd);
        
        print_metadata();

    }

    void sync_to_file(const char *out_path) {
      int fd = open(out_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
      if (write(fd, image_buffer_, image_size_) != image_size_)
        FATAL("[-] image sync to file %s failed.", out_path);
      close(fd);
    }

    bool release_metadata(std::set<uint64_t> &meta_blocks, int meta_image_fd, bool in_block) {
 
      std::set<uint64_t>::iterator it = meta_blocks.begin();

      // for (auto no : meta_blocks) 
      //  std::cout << no << std::endl;

      do {
        extent_t extent;
        extent.first = in_block ? (*it) * block_size_ : (*it);
        extent.second = block_size_;
        uint64_t cur_offset = extent.first;

        // std::cout << "visit " << *it << std::endl;
        for (it++; it != meta_blocks.end(); it++) {
          // std::cout << "visit " << *it << std::endl;
          // std::cout << cur_offset + block_size << std::endl;
          if (cur_offset + block_size_ == (in_block ? (*it) * block_size_ : (*it))) {
            extent.second += block_size_;
            cur_offset += block_size_;
          } else {
            break;
          }
        }
        
        metadata_.push_back(extent);
        // std::cout << "offset: " << extent.first << "size: " << extent.second << std::endl;

        if (meta_image_fd > 0) {
          if (write(meta_image_fd, (char *)image_buffer_ + extent.first, extent.second) != extent.second) 
            return false;
        }

      } while (it != meta_blocks.end());

      return true;

    }

    void print_metadata() {
      for (auto extent : metadata_) 
        printf("offset: 0x%lx size: 0x%lx\n", extent.first, extent.second);
    }

   private:
      
    const char *fstype_;

   protected:

    // std::set<uint64_t> metadata_blocks; 
    std::vector<extent_t> metadata_;
    uint32_t block_size_;
    uint32_t block_count_;

    size_t image_size_;
    // char *image_path_;
    void *image_buffer_;

};

#endif

