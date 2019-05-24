#include <set>

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"

FILE *out_log;
int in_image_fd;
int out_image_fd;
std::set<blk64_t> block_indexes;

struct find_block {
  struct ext2_inode *inode;
};

static int find_block_helper(ext2_filsys fs EXT2FS_ATTR((unused)),
			     blk64_t *blocknr, e2_blkcnt_t blockcnt,
			     blk64_t ref_blk EXT2FS_ATTR((unused)),
			     int ref_offset EXT2FS_ATTR((unused)),
			     void *priv_data)
{
  struct find_block *fb = (struct find_block *)priv_data;
	if (S_ISDIR(fb->inode->i_mode) || blockcnt < 0) {
		// ext2fs_mark_block_bitmap2(fb->bitmap, *blocknr);
		block_indexes.insert(*blocknr);
	}

	return 0;
}

int find_super_and_bgd(ext2_filsys fs, dgrp_t group)
{
	blk64_t	super_blk, old_desc_blk, new_desc_blk;
	blk_t	used_blks;
	int	old_desc_blocks, num_blocks;

	ext2fs_super_and_bgd_loc2(fs, group, &super_blk,
				  &old_desc_blk, &new_desc_blk, &used_blks);

	if (ext2fs_has_feature_meta_bg(fs->super))
		old_desc_blocks = fs->super->s_first_meta_bg;
	else
		old_desc_blocks = fs->desc_blocks + fs->super->s_reserved_gdt_blocks;

	if (super_blk || (group == 0))
		// ext2fs_mark_block_bitmap2(bmap, super_blk);
		block_indexes.insert(super_blk);
		
	if ((group == 0) && (fs->blocksize == 1024) &&
	    EXT2FS_CLUSTER_RATIO(fs) > 1)
		// ext2fs_mark_block_bitmap2(bmap, 0);
		block_indexes.insert(0);


	if (old_desc_blk) {
		num_blocks = old_desc_blocks;
		if (old_desc_blk + num_blocks >= ext2fs_blocks_count(fs->super))
			num_blocks = ext2fs_blocks_count(fs->super) - old_desc_blk;
		// ext2fs_mark_block_bitmap_range2(bmap, old_desc_blk, num_blocks);
		for (blk64_t i; i < old_desc_blk + num_blocks; i++)	
			block_indexes.insert(i);
	}
	if (new_desc_blk)
		// ext2fs_mark_block_bitmap2(bmap, new_desc_blk);
		block_indexes.insert(new_desc_blk);


	num_blocks = ext2fs_group_blocks_count(fs, group);
	num_blocks -= 2 + fs->inode_blocks_per_group + used_blks;

	return num_blocks  ;
}

static errcode_t find_metadata_blocks(ext2_filsys fs, ext2fs_block_bitmap bitmap)
{
	blk64_t b, c;
  ext2_inode_scan scan;
  ext2_ino_t ino;
  struct ext2_inode inode;
  struct find_block fb;
  errcode_t retval;

  printf("total block count: %d\n", fs->super->s_blocks_count);

  for (dgrp_t i = 0; i < fs->group_desc_count; i++) {
    
    find_super_and_bgd(fs, i);

		/* bitmaps and inode table */
		b = ext2fs_block_bitmap_loc(fs, i);
		// ext2fs_mark_block_bitmap2(bitmap, b);
		block_indexes.insert(i);

		b = ext2fs_inode_bitmap_loc(fs, i);
		// ext2fs_mark_block_bitmap2(bitmap, b);
		block_indexes.insert(i);

		c = ext2fs_inode_table_loc(fs, i);
		// ext2fs_mark_block_bitmap_range2(bitmap, c, fs->inode_blocks_per_group);
		for (blk64_t j = c; j < c + fs->inode_blocks_per_group; j++)
			block_indexes.insert(j);

  }

  /* scan inodes */
  fb.inode = &inode;
  memset(&inode, 0, sizeof(inode));

  retval = ext2fs_open_inode_scan(fs, 0, &scan);
  if (retval)
    goto out;

  retval = ext2fs_get_next_inode_full(scan, &ino, &inode, sizeof(inode));
  if (retval)
    goto out2;

  while (ino) {
    // printf("ino: %d\n", ino);
    if (inode.i_links_count == 0)
      goto next_loop;

    b = ext2fs_file_acl_block(fs, &inode);
    if (b) {
      // ext2fs_mark_block_bitmap2(bitmap, b);
			block_indexes.insert(b);
    }

    if ((inode.i_flags & EXT4_INLINE_DATA_FL) ||
        S_ISLNK(inode.i_mode) || S_ISFIFO(inode.i_mode) ||
        S_ISCHR(inode.i_mode) || S_ISBLK(inode.i_mode) ||
        S_ISSOCK(inode.i_mode))
          goto next_loop;

    retval = ext2fs_block_iterate3(fs, ino, BLOCK_FLAG_READ_ONLY,
                                NULL, find_block_helper, &fb);
   	
    if (retval)
      goto out2;

next_loop:
    retval = ext2fs_get_next_inode_full(scan, &ino, &inode, sizeof(inode));
    if (retval)
      goto out2;
  }
 
out2:
   ext2fs_close_inode_scan(scan);
out:
	// printf("cnt: %ld\n", block_indexes.size());

	return 0;
}

static int process_fs(const char *fsname)
{

  errcode_t ret;
  ext2_filsys fs = NULL;
  ext2fs_block_bitmap bitmap;
  unsigned int block_size;
  void *tmp_buffer;

  ret = ext2fs_open(fsname, EXT2_FLAG_64BITS, 0, 0, unix_io_manager, &fs);

  if (ret) {
    fprintf(stderr, "%s: failed to open filesystem.\n", fsname);
    return 1;
  }

  ret = ext2fs_allocate_block_bitmap(fs, "metadata block map", &bitmap);

  if (ret) {
    fprintf(stderr, "%s: unable to create block bitmap\n", fsname);
    goto fail;
  }

  find_metadata_blocks(fs, bitmap);

  block_size = 1 << (10 + fs->super->s_log_block_size);
  tmp_buffer = malloc(block_size);

  for (std::set<blk64_t>::iterator it = block_indexes.begin(); 
      it != block_indexes.end(); 
      ++it) {
    fprintf(out_log, "%lld\n", *it);

    pread(in_image_fd, tmp_buffer, block_size, (*it) * block_size);
    write(out_image_fd, tmp_buffer, block_size);
   }

  free(tmp_buffer); 

fail:
  ext2fs_close_free(&fs);
  return 1;
}

int main(int argc, char *argv[]) {
  
  if (argc < 5) {
    fprintf(stderr, "%s [c|d] [image] [compressed image] [log]", argv[0]);
    return 1;
  }

  if (!strcmp(argv[1], "c")) {
      in_image_fd = open(argv[2], O_RDONLY);
      out_image_fd = open(argv[3], O_CREAT|O_RDWR|O_TRUNC, 0666);
      out_log = fopen(argv[4], "w");
  
      process_fs(argv[2]);

      close(out_image_fd);
      close(in_image_fd);
      fclose(out_log);
  } else if (!strcmp(argv[1], "d")) {
    ;         
  } else {
    fprintf(stderr, "invalid option\n");
    return 1;
  }
	return 0;
}
