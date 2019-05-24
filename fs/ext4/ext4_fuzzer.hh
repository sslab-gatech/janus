#ifndef FS_FUZZ_EXT4_FUZZER_HH
#define FS_FUZZ_EXT4_FUZZER_HH

#include "fsfuzzer.hh"

static class ext4_fuzzer: public fsfuzzer 
{
    private:
      std::vector<uint64_t> journal_blocks;

    public:
      ext4_fuzzer(): fsfuzzer("ext4") { }

      void fix_checksum();

      void fix_general_checksum();

      void compress(const char *in_path, void *buffer, const char *meta_path = NULL);

      void decompress(const void *meta_buffer, size_t meta_len, bool checksum = true);

      void general_decompress(const void *meta_buffer, size_t meta_len, bool checksum = true);

} ext4_fuzzer;

#endif
