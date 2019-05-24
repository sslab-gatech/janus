#ifndef FS_FUZZ_BTRFS_HH
#define FS_FUZZ_BTRFS_HH

#include <stdint.h>

#define KB 1024ull
#define MB 1024ull*KB
#define GB 1024ull*MB
#define TB 1024ull*GB

/* address translation structure */
struct address_range {
  uint64_t start;
  uint64_t length;

  bool operator < (const address_range& ar)  const {
    if (start + length <= ar.start) {
      return true;
    }
    return false;
  }
};
typedef struct address_range address_range;

/* btrfs structure */

#define UUID_LEN 0x10
#define CHECKSUM_LEN 0x20
#define SUPERBLOCK_SIZE 0x1000

const uint64_t BTRFS_SUPERBLOCK_OFFSETS[] = {64*KB, 64*MB, 256*GB, 1024*TB, 0};

enum btrfs_key_type : uint8_t {
  DEVICE_ITEM = 0xd8,
  CHUNK_ITEM = 0xe4,
  ROOT_ITEM = 0x84
};
typedef btrfs_key_type btrfs_key_type;


typedef struct {
  uint64_t seconds;
  uint32_t nanoseconds;
} __attribute__((packed)) btrfs_time;

typedef struct {
  uint64_t object_id;
  btrfs_key_type type;
  uint64_t offset;
} __attribute__((packed)) btrfs_key;

typedef struct {
  btrfs_key key;
  uint64_t block_number;
  uint64_t generation;
} __attribute__((packed)) btrfs_key_pointer;

typedef struct {
  btrfs_key key;
  uint32_t data_offset;
  uint32_t data_size;
} __attribute__((packed)) btrfs_item_pointer;

typedef struct {
  uint8_t csum[CHECKSUM_LEN];
  uint8_t uuid[UUID_LEN];
  uint64_t logical_address;
  uint8_t flags[7];
  uint8_t backref_revision;
  uint8_t chunk_tree_uuid[UUID_LEN];
  uint64_t generation;
  uint64_t parent_tree_id;
  uint32_t item_count;
  uint8_t level;
} __attribute__((packed)) btrfs_header;

typedef struct {
  uint64_t generation;
  uint64_t last_transid;
  uint64_t st_size;
  uint64_t st_blocks;
  uint64_t block_group;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint32_t st_mode;
  uint64_t st_rdev;
  uint64_t flags;
  uint64_t sequence;
  uint8_t rsv0[0x20];
  btrfs_time atime;
  btrfs_time ctime;
  btrfs_time mtime;
  btrfs_time otime;
} __attribute__((packed)) btrfs_inode_item;

typedef struct {
  btrfs_inode_item inode;
  uint64_t expected_generation;
  uint64_t tree_root_object_id;
  uint64_t root_block_num;
  uint64_t byte_limit;
  uint64_t bytes_used;
  uint64_t last_snapshot_generation;
  uint64_t flags;
  uint32_t reference_count;
  btrfs_key drop_progress;
  uint8_t drop_level;
  uint8_t level;
} __attribute__((packed)) btrfs_root_item;

typedef struct {
  uint64_t device_id;
  uint64_t offset;
  uint8_t uuid[UUID_LEN];
} __attribute__((packed)) btrfs_stripe;

typedef struct {
  uint64_t chunk_size_bytes;
  uint64_t object_id;
  uint64_t stripe_size;
  uint64_t type;
  uint32_t preferred_io_alignment;
  uint32_t preferred_io_width;
  uint32_t minimum_io_size;
  uint16_t stripe_count;
  uint16_t sub_stripes;
  btrfs_stripe stripes[0];
} __attribute__((packed)) btrfs_chunk_item;

typedef struct {
  uint64_t device_id;
  uint64_t byte_count;
  uint64_t bytes_used;
  uint32_t preferred_io_alignment;
  uint32_t preferred_io_width;
  uint32_t minimum_io_size;
  uint64_t type;
  uint64_t generation;
  uint64_t start_offset;
  uint32_t device_group;
  uint8_t seek_speed;
  uint8_t bandwidth;
  uint8_t device_uuid[UUID_LEN];
  uint8_t fs_uuid[UUID_LEN];
} __attribute__((packed)) btrfs_device_item;

typedef struct {
  uint8_t csum[CHECKSUM_LEN];
  uint8_t uuid[UUID_LEN];
  uint64_t cur_block_phys_addr;
  uint64_t flags;
  char magic[8];
  uint64_t generation;
  uint64_t root_tree_root_addr;
  uint64_t chunk_tree_root_addr;
  uint64_t log_tree_root_addr;
  uint64_t log_root_transid;
  uint64_t total_bytes;
  uint64_t bytes_used;
  uint64_t root_dir_objectid;
  uint64_t num_devices;
  uint32_t sector_size;
  uint32_t node_size;
  uint32_t leaf_size;
  uint32_t stripe_size;
  uint32_t key_chunk_item_table_len;
  uint64_t chunk_root_generation;
  uint64_t compat_flags;
  uint64_t compat_ro_flags;
  uint64_t incompat_flags;
  uint16_t checksum_type;
  uint8_t root_level;
  uint8_t chunk_root_level;
  uint8_t log_root_level;
  btrfs_device_item dev_item;
  char label[0x100];
  uint64_t cache_generation;
  uint64_t uuid_tree_generation;
  uint8_t reserved[0xf0];
  uint8_t key_chunk_item_table[0];
} __attribute__((packed)) btrfs_super_block ;

#endif
