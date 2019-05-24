#include <sys/stat.h>
#include <set>
#include <map>

#include "btrfs_fuzzer.hh"
#include "btrfs.hh"
#include "utils.hh"
extern "C" {
  #include "crc32c.h"
}

void btrfs_fuzzer::fix_checksum() {
  uint32_t crc;
  uint64_t block_size;
  crc32c_init();

  for (std::set<uint64_t>::iterator it = this->metadata_blocks.begin();
      it != this->metadata_blocks.end(); ++it) {
    block_size = block_size_;
    for (int i = 0; BTRFS_SUPERBLOCK_OFFSETS[i] != 0; i++) {
      if (*it == BTRFS_SUPERBLOCK_OFFSETS[i]) {
        block_size = SUPERBLOCK_SIZE;
        break;
      }
    }

    crc = crc32c(-1, (char *)image_buffer_ + (*it) + CHECKSUM_LEN,
        block_size - CHECKSUM_LEN);
    memcpy((char*)image_buffer_ + (*it), &crc, 4);
  }

}

void btrfs_fuzzer::fix_general_checksum() {

    uint8_t buf[4096];
    crc32c_init();

    memcpy(buf, (char *)image_buffer_ + (1 << 16), sizeof(buf));

    uint32_t crc = crc32c(-1, buf + 32, sizeof(buf) - 32);
    memcpy(buf, &crc, sizeof(crc));

    memcpy((char *)image_buffer_ + (1 << 16), buf, sizeof(buf));
}

uint64_t btrfs_fuzzer::logical_to_physical(uint64_t logical) {
  std::map<address_range, uint64_t>::iterator it =
      this->address_map.find({logical, 1});
  if (it == this->address_map.end()) {
    return -1;
  }
  return it->second + (logical - it->first.start);
}

void btrfs_fuzzer::btrfs_parse_tree(uint64_t node_vaddr) {
  if (node_vaddr == 0) {
    return;
  }

  uint64_t node_paddr = logical_to_physical(node_vaddr);
  if (node_paddr == (uint64_t)-1) {
    FATAL("[-] image compression failed. virtual address (%lu) not found\n",
        node_paddr);
  }
  btrfs_header *header =
      (btrfs_header*)((uint8_t*)image_buffer_ + node_paddr);

  this->metadata_blocks.insert(node_paddr);

  if (header->level == 0) {
    // Leaf node
  } else {
    btrfs_key_pointer *key_ptr = (btrfs_key_pointer*)(header + 1);

    for (int i = 0; i < (int)header->item_count; i++) {
      btrfs_parse_tree(key_ptr->block_number);
      key_ptr++;
    }
  }
}

void btrfs_fuzzer::btrfs_parse_root_tree(uint64_t node_vaddr) {
  uint64_t node_paddr = logical_to_physical(node_vaddr);
  if (node_paddr == (uint64_t)-1) {
    FATAL("[-] image compression failed. virtual address (%lu) not found\n",
        node_paddr);
  }
  btrfs_header *header =
      (btrfs_header*)((uint8_t*)image_buffer_ + node_paddr);

  this->metadata_blocks.insert(node_paddr);

  if (header->level == 0) {
    btrfs_item_pointer *item_ptr = (btrfs_item_pointer*)(header + 1);

    for (int i = 0; i < (int)header->item_count; i++) {
      if (item_ptr->key.type == ROOT_ITEM) {
        btrfs_root_item *root_item = (btrfs_root_item*)((uint8_t*)header
                                       + sizeof(btrfs_header)
                                       + item_ptr->data_offset);
        btrfs_parse_tree(root_item->root_block_num);
      } else {
        // Items related to root tree directory
      }

      item_ptr++;
    }
  } else {
    // ???: root tree should contain only one level.
  }
}

void btrfs_fuzzer::btrfs_parse_chunk_tree(uint64_t node_vaddr) {
  uint64_t node_paddr = logical_to_physical(node_vaddr);
  if (node_paddr == (uint64_t)-1) {
    FATAL("[-] image compression failed. virtual address (%lu) not found\n",
        node_paddr);
  }
  btrfs_header *header =
      (btrfs_header*)((uint8_t*)image_buffer_ + node_paddr);

  this->metadata_blocks.insert(node_paddr);

  if (header->level == 0) {
    btrfs_item_pointer *item_ptr = (btrfs_item_pointer*)(header + 1);

    for (int i = 0; i < (int)header->item_count; i++) {
      if (item_ptr->key.type == DEVICE_ITEM) {
        // Do nothing.
      } else if (item_ptr->key.type == CHUNK_ITEM) {
        btrfs_chunk_item *chunk_item = (btrfs_chunk_item*)((uint8_t*)header
                                       + sizeof(btrfs_header)
                                       + item_ptr->data_offset);
        uint64_t logical = item_ptr->key.offset;
        uint64_t length = chunk_item->chunk_size_bytes;
        uint64_t physical = chunk_item->stripes[0].offset;

        this->address_map[{logical, length}] = physical;
      }

      item_ptr++;
    }
  } else {
    btrfs_key_pointer *key_ptr = (btrfs_key_pointer*)(header + 1);

    for (int i = 0; i < (int)header->item_count; i++) {
      btrfs_parse_chunk_tree(key_ptr->block_number);
      key_ptr++;
    }
  }
}

void btrfs_fuzzer::btrfs_parse_superblock(btrfs_super_block *sb) {
  // Load superblock
  for (int i = 0; BTRFS_SUPERBLOCK_OFFSETS[i] != 0; i++) {
    uint64_t offset = BTRFS_SUPERBLOCK_OFFSETS[i];

    if (image_size_ < offset) {
      break;
    }

    // Only parse the first supberblock.
    if (i == 0) {
      memcpy(sb, (uint8_t*)image_buffer_ + offset, SUPERBLOCK_SIZE);
    }

    this->metadata_blocks.insert(offset);
  }

  // Bootstrap the address translation table.
  // Not handling multi devices (RAID) and DUP now.
  uint64_t table_bytes = sb->key_chunk_item_table_len;
  uint8_t *table = sb->key_chunk_item_table;
  while (table_bytes > 0) {
    btrfs_key *key = (btrfs_key*)table;
    btrfs_chunk_item *chunk_item =
        (btrfs_chunk_item*)(table + sizeof(btrfs_key));
    uint64_t logical = key->offset;
    uint64_t length = chunk_item->chunk_size_bytes;
    uint64_t physical = chunk_item->stripes[0].offset;

    this->address_map[{logical, length}] = physical;

    int offset = sizeof(btrfs_key) + sizeof(btrfs_chunk_item)
                 + sizeof(btrfs_stripe)*chunk_item->stripe_count;
    table += offset;
    table_bytes -= offset;
  }
}

void btrfs_fuzzer::compress(const char *in_path, void *buffer,
                           const char *meta_path) {

  bool generate_meta_image = meta_path != NULL;

  int in_image_fd = open(in_path, O_RDONLY);
  if (in_image_fd < 0) {
    FATAL("[-] image %s compression failed.", in_path);
  }

  struct stat st;
  if (fstat(in_image_fd, &st) != 0) {
      FATAL("[-] image %s compression failed.", in_path);
  }

  image_size_ = st.st_size;
  image_buffer_ = buffer;

  if (read(in_image_fd, image_buffer_, image_size_) != image_size_) 
    FATAL("[-] image %s compression failed.", in_path);

  close(in_image_fd);

  int meta_image_fd = -1;
  if (generate_meta_image) {
    meta_image_fd = open(meta_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (meta_image_fd < 0) {
      FATAL("[-] image %s compression failed.", in_path);
    }
  }

  btrfs_super_block *sb = (btrfs_super_block*)malloc(SUPERBLOCK_SIZE);

  btrfs_parse_superblock(sb);
  if (sb->node_size != sb->leaf_size) {
    // How often will this happen?
    printf("Need some attention.\n");
  }
  block_size_ = sb->node_size;

  btrfs_parse_chunk_tree(sb->chunk_tree_root_addr);
  btrfs_parse_root_tree(sb->root_tree_root_addr);
  btrfs_parse_tree(sb->log_tree_root_addr);

  if (!release_metadata(this->metadata_blocks, meta_image_fd, false)) 
    FATAL("[-] image %s compression failed.", in_path);

  if (generate_meta_image) 
    close(meta_image_fd);

  // print_metadata();

}

void btrfs_fuzzer::decompress(
    const void *meta_buffer, size_t meta_len, bool checksum) {

  size_t meta_offset = 0;

  for (extent_t &extent : metadata_) {
    memcpy((char *)image_buffer_ + extent.first,
        (char *)meta_buffer + meta_offset, extent.second);
    meta_offset += extent.second;
  }

  if (checksum)
    fix_checksum();

}

void btrfs_fuzzer::general_decompress(
    const void *meta_buffer, size_t meta_len, bool checksum) {

  size_t meta_offset = 0;

  for (extent_t &extent : metadata_) {
    memcpy((char *)image_buffer_ + extent.first,
        (char *)meta_buffer + meta_offset, extent.second);
    meta_offset += extent.second;
  }

  if (checksum)
    fix_general_checksum();

}
