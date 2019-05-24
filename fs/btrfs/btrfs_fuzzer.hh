#ifndef FS_FUZZ_BTRFS_FUZZER_HH
#define FS_FUZZ_BTRFS_FUZZER_HH

#include <map>

#include "fsfuzzer.hh"
#include "btrfs.hh"

static class btrfs_fuzzer: public fsfuzzer {
  public:
    btrfs_fuzzer(): fsfuzzer("btrfs") {}

    void fix_checksum();

    void fix_general_checksum();

    void compress(const char *in_path, void *buffer,
                  const char *meta_path = NULL);

    void decompress(const void *meta_buffer, size_t meta_len,
                    bool checksum = true);

    void general_decompress(const void *meta_buffer, size_t meta_len,
                    bool checksum = true);

    uint64_t logical_to_physical(uint64_t logical);
    void btrfs_parse_superblock(btrfs_super_block *sb);
    void btrfs_parse_chunk_tree(uint64_t node_vaddr);
    void btrfs_parse_root_tree(uint64_t node_vaddr);
    void btrfs_parse_tree(uint64_t node_vaddr);

  protected:
    std::map<address_range, uint64_t> address_map;
  
  private:
    std::set<uint64_t> metadata_blocks;

} btrfs_fuzzer;

#endif
