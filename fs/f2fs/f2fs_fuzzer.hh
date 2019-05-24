#ifndef FS_FUZZ_F2FS_FUZZER_HH
#define FS_FUZZ_F2FS_FUZZER_HH

#include "fsfuzzer.hh"

typedef uint32_t    block_t;
typedef uint32_t     nid_t;
typedef unsigned long   pgoff_t;
typedef unsigned short  umode_t;

#define MAX_PATH_LEN        64
#define MAX_DEVICES     8
#define MAX_VOLUME_NAME     512

#define VERSION_LEN 256

#define F2FS_MAX_EXTENSION      64  /* # of extension entries */
#define F2FS_SUPER_OFFSET       1024    /* byte-size offset */
#define F2FS_BYTES_TO_BLK(bytes)    ((bytes) >> F2FS_BLKSIZE_BITS)
#define F2FS_BLKSIZE            4096    /* support only 4KB block */
#define F2FS_BLKSIZE_BITS 12
#define F2FS_MAX_QUOTAS     3
#define F2FS_SUPER_MAGIC	0xF2F52010	/* F2FS Magic Number */

#define MAX_ACTIVE_LOGS	16
#define MAX_ACTIVE_NODE_LOGS	8
#define MAX_ACTIVE_DATA_LOGS	8

struct f2fs_device {
	__u8 path[MAX_PATH_LEN];
	__le32 total_segments;
} __attribute__((packed));

struct f2fs_super_block {
	__le32 magic;			/* Magic Number */
	__le16 major_ver;		/* Major Version */
	__le16 minor_ver;		/* Minor Version */
	__le32 log_sectorsize;		/* log2 sector size in bytes */
	__le32 log_sectors_per_block;	/* log2 # of sectors per block */
	__le32 log_blocksize;		/* log2 block size in bytes */
	__le32 log_blocks_per_seg;	/* log2 # of blocks per segment */
	__le32 segs_per_sec;		/* # of segments per section */
	__le32 secs_per_zone;		/* # of sections per zone */
	__le32 checksum_offset;		/* checksum offset inside super block */
	__le64 block_count;		/* total # of user blocks */
	__le32 section_count;		/* total # of sections */
	__le32 segment_count;		/* total # of segments */
	__le32 segment_count_ckpt;	/* # of segments for checkpoint */
	__le32 segment_count_sit;	/* # of segments for SIT */
	__le32 segment_count_nat;	/* # of segments for NAT */
	__le32 segment_count_ssa;	/* # of segments for SSA */
	__le32 segment_count_main;	/* # of segments for main area */
	__le32 segment0_blkaddr;	/* start block address of segment 0 */
	__le32 cp_blkaddr;		/* start block address of checkpoint */
	__le32 sit_blkaddr;		/* start block address of SIT */
	__le32 nat_blkaddr;		/* start block address of NAT */
	__le32 ssa_blkaddr;		/* start block address of SSA */
	__le32 main_blkaddr;		/* start block address of main area */
	__le32 root_ino;		/* root inode number */
	__le32 node_ino;		/* node inode number */
	__le32 meta_ino;		/* meta inode number */
	__u8 uuid[16];			/* 128-bit uuid for volume */
	__le16 volume_name[MAX_VOLUME_NAME];	/* volume name */
	__le32 extension_count;		/* # of extensions below */
	__u8 extension_list[F2FS_MAX_EXTENSION][8];	/* extension array */
	__le32 cp_payload;
	__u8 version[VERSION_LEN];	/* the kernel version */
	__u8 init_version[VERSION_LEN];	/* the initial kernel version */
	__le32 feature;			/* defined features */
	__u8 encryption_level;		/* versioning level for encryption */
	__u8 encrypt_pw_salt[16];	/* Salt used for string2key algorithm */
	struct f2fs_device devs[MAX_DEVICES];	/* device list */
	__le32 qf_ino[F2FS_MAX_QUOTAS];	/* quota inode numbers */
	__u8 reserved[315];		/* valid reserved region */
} __attribute__((packed));

struct f2fs_checkpoint {
	__le64 checkpoint_ver;		/* checkpoint block version number */
	__le64 user_block_count;	/* # of user blocks */
	__le64 valid_block_count;	/* # of valid blocks in main area */
	__le32 rsvd_segment_count;	/* # of reserved segments for gc */
	__le32 overprov_segment_count;	/* # of overprovision segments */
	__le32 free_segment_count;	/* # of free segments in main area */

	/* information of current node segments */
	__le32 cur_node_segno[MAX_ACTIVE_NODE_LOGS];
	__le16 cur_node_blkoff[MAX_ACTIVE_NODE_LOGS];
	/* information of current data segments */
	__le32 cur_data_segno[MAX_ACTIVE_DATA_LOGS];
	__le16 cur_data_blkoff[MAX_ACTIVE_DATA_LOGS];
	__le32 ckpt_flags;		/* Flags : umount and journal_present */
	__le32 cp_pack_total_block_count;	/* total # of one cp pack */
	__le32 cp_pack_start_sum;	/* start block number of data summary */
	__le32 valid_node_count;	/* Total number of valid nodes */
	__le32 valid_inode_count;	/* Total number of valid inodes */
	__le32 next_free_nid;		/* Next free node number */
	__le32 sit_ver_bitmap_bytesize;	/* Default value 64 */
	__le32 nat_ver_bitmap_bytesize; /* Default value 256 */
	__le32 checksum_offset;		/* checksum offset inside cp block */
	__le64 elapsed_time;		/* mounted time */
	/* allocation type of current segment */
	unsigned char alloc_type[MAX_ACTIVE_LOGS];

	/* SIT and NAT version bitmap */
	unsigned char sit_nat_version_bitmap[1];
} __attribute__((packed));

static class f2fs_fuzzer: public fsfuzzer 
{
    public:
      f2fs_fuzzer(): fsfuzzer("f2fs")
		// cp1_page1(NULL), cp1_page2(NULL), cp2_page1(NULL), cp2_page2(NULL)
 	  { 
		;
	  }

	  ~f2fs_fuzzer() {
	  }

      void fix_checksum();
      void fix_general_checksum();

      void compress(const char *in_path, void *buffer, const char *meta_path);

      void decompress(const void *meta_buffer, size_t meta_len, bool checksum = true);
      void general_decompress(const void *meta_buffer, size_t meta_len, bool checksum = true);

    private:
	
      uint64_t segment_size_;

      struct f2fs_super_block sb;
	  
	  uint64_t sb1_off, sb2_off;
	  uint64_t cp1_page1_off, cp1_page2_off;
	  uint64_t cp1_page1_crc, cp1_page2_crc;
	  uint64_t cp2_page1_off, cp2_page2_off;
	  uint64_t cp2_page1_crc, cp2_page2_crc;
      std::set<uint64_t> meta_offsets;

      uint32_t read32(uint32_t offset);
	  uint64_t blk2off(uint64_t nr) { return nr * block_size_; }
	  void add_checkpoint();
      void add_superblock();
	  void add_sit();
	  void add_nat();
	  void add_ssa();
	  void add_main(const char *in_path);

} f2fs_fuzzer;

#endif

