/**
 * segment.c
 *
 * Many parts of codes are copied from Linux kernel/fs/f2fs.
 *
 * Copyright (C) 2015 Huawei Ltd.
 * Witten by:
 *   Hou Pengyang <houpengyang@huawei.com>
 *   Liu Shuoran <liushuoran@huawei.com>
 *   Jaegeuk Kim <jaegeuk@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"
#include "node.h"

static void write_inode(u64 blkaddr, struct f2fs_node *inode)
{
	if (c.feature & cpu_to_le32(F2FS_FEATURE_INODE_CHKSUM))
		inode->i.i_inode_checksum =
			cpu_to_le32(f2fs_inode_chksum(inode));
	ASSERT(dev_write_block(inode, blkaddr) >= 0);
}

void reserve_new_block(struct f2fs_sb_info *sbi, block_t *to,
			struct f2fs_summary *sum, int type)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct seg_entry *se;
	u64 blkaddr, offset;
	u64 old_blkaddr = *to;

	blkaddr = SM_I(sbi)->main_blkaddr;

	if (find_next_free_block(sbi, &blkaddr, 0, type)) {
		ERR_MSG("Not enough space to allocate blocks");
		ASSERT(0);
	}

	se = get_seg_entry(sbi, GET_SEGNO(sbi, blkaddr));
	offset = OFFSET_IN_SEG(sbi, blkaddr);
	se->type = type;
	se->valid_blocks++;
	f2fs_set_bit(offset, (char *)se->cur_valid_map);
	if (c.func == FSCK) {
		f2fs_set_main_bitmap(sbi, blkaddr, type);
		f2fs_set_sit_bitmap(sbi, blkaddr);
	}

	if (old_blkaddr == NULL_ADDR) {
		sbi->total_valid_block_count++;
		if (c.func == FSCK)
			fsck->chk.valid_blk_cnt++;
	}
	se->dirty = 1;

	/* read/write SSA */
	*to = (block_t)blkaddr;
	update_sum_entry(sbi, *to, sum);
}

void new_data_block(struct f2fs_sb_info *sbi, void *block,
				struct dnode_of_data *dn, int type)
{
	struct f2fs_summary sum;
	struct node_info ni;
	unsigned int blkaddr = datablock_addr(dn->node_blk, dn->ofs_in_node);

	ASSERT(dn->node_blk);
	memset(block, 0, BLOCK_SZ);

	get_node_info(sbi, dn->nid, &ni);
	set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version);
	reserve_new_block(sbi, &dn->data_blkaddr, &sum, type);

	if (blkaddr == NULL_ADDR)
		inc_inode_blocks(dn);
	else if (blkaddr == NEW_ADDR)
		dn->idirty = 1;
	set_data_blkaddr(dn);
}

u64 f2fs_read(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
					u64 count, pgoff_t offset)
{
	struct dnode_of_data dn;
	struct node_info ni;
	struct f2fs_node *inode;
	char *blk_buffer;
	u64 filesize;
	u64 off_in_blk;
	u64 len_in_blk;
	u64 read_count;
	u64 remained_blkentries;
	block_t blkaddr;
	void *index_node = NULL;

	memset(&dn, 0, sizeof(dn));

	/* Memory allocation for block buffer and inode. */
	blk_buffer = calloc(BLOCK_SZ, 2);
	ASSERT(blk_buffer);
	inode = (struct f2fs_node*)(blk_buffer + BLOCK_SZ);

	/* Read inode */
	get_node_info(sbi, ino, &ni);
	ASSERT(dev_read_block(inode, ni.blk_addr) >= 0);
	ASSERT(!S_ISDIR(le16_to_cpu(inode->i.i_mode)));
	ASSERT(!S_ISLNK(le16_to_cpu(inode->i.i_mode)));

	/* Adjust count with file length. */
	filesize = le64_to_cpu(inode->i.i_size);
	if (offset > filesize)
		count = 0;
	else if (count + offset > filesize)
		count = filesize - offset;

	/* Main loop for file blocks */
	read_count = remained_blkentries = 0;
	while (count > 0) {
		if (remained_blkentries == 0) {
			set_new_dnode(&dn, inode, NULL, ino);
			get_dnode_of_data(sbi, &dn, F2FS_BYTES_TO_BLK(offset),
					LOOKUP_NODE);
			if (index_node)
				free(index_node);
			index_node = (dn.node_blk == dn.inode_blk) ?
							NULL : dn.node_blk;
			remained_blkentries = ADDRS_PER_PAGE(dn.node_blk);
		}
		ASSERT(remained_blkentries > 0);

		blkaddr = datablock_addr(dn.node_blk, dn.ofs_in_node);
		if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR)
			break;

		off_in_blk = offset % BLOCK_SZ;
		len_in_blk = BLOCK_SZ - off_in_blk;
		if (len_in_blk > count)
			len_in_blk = count;

		/* Read data from single block. */
		if (len_in_blk < BLOCK_SZ) {
			ASSERT(dev_read_block(blk_buffer, blkaddr) >= 0);
			memcpy(buffer, blk_buffer + off_in_blk, len_in_blk);
		} else {
			/* Direct read */
			ASSERT(dev_read_block(buffer, blkaddr) >= 0);
		}

		offset += len_in_blk;
		count -= len_in_blk;
		buffer += len_in_blk;
		read_count += len_in_blk;

		dn.ofs_in_node++;
		remained_blkentries--;
	}
	if (index_node)
		free(index_node);
	free(blk_buffer);

	return read_count;
}

u64 f2fs_write(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
					u64 count, pgoff_t offset)
{
	struct dnode_of_data dn;
	struct node_info ni;
	struct f2fs_node *inode;
	char *blk_buffer;
	u64 off_in_blk;
	u64 len_in_blk;
	u64 written_count;
	u64 remained_blkentries;
	block_t blkaddr;
	void* index_node = NULL;
	int idirty = 0;

	/* Memory allocation for block buffer and inode. */
	blk_buffer = calloc(BLOCK_SZ, 2);
	ASSERT(blk_buffer);
	inode = (struct f2fs_node*)(blk_buffer + BLOCK_SZ);

	/* Read inode */
	get_node_info(sbi, ino, &ni);
	ASSERT(dev_read_block(inode, ni.blk_addr) >= 0);
	ASSERT(!S_ISDIR(le16_to_cpu(inode->i.i_mode)));
	ASSERT(!S_ISLNK(le16_to_cpu(inode->i.i_mode)));

	/* Main loop for file blocks */
	written_count = remained_blkentries = 0;
	while (count > 0) {
		if (remained_blkentries == 0) {
			set_new_dnode(&dn, inode, NULL, ino);
			get_dnode_of_data(sbi, &dn, F2FS_BYTES_TO_BLK(offset),
					ALLOC_NODE);
			idirty |= dn.idirty;
			if (index_node)
				free(index_node);
			index_node = (dn.node_blk == dn.inode_blk) ?
							NULL : dn.node_blk;
			remained_blkentries = ADDRS_PER_PAGE(dn.node_blk);
		}
		ASSERT(remained_blkentries > 0);

		blkaddr = datablock_addr(dn.node_blk, dn.ofs_in_node);
		if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR) {
			new_data_block(sbi, blk_buffer, &dn, CURSEG_WARM_DATA);
			blkaddr = dn.data_blkaddr;
		}

		off_in_blk = offset % BLOCK_SZ;
		len_in_blk = BLOCK_SZ - off_in_blk;
		if (len_in_blk > count)
			len_in_blk = count;

		/* Write data to single block. */
		if (len_in_blk < BLOCK_SZ) {
			ASSERT(dev_read_block(blk_buffer, blkaddr) >= 0);
			memcpy(blk_buffer + off_in_blk, buffer, len_in_blk);
			ASSERT(dev_write_block(blk_buffer, blkaddr) >= 0);
		} else {
			/* Direct write */
			ASSERT(dev_write_block(buffer, blkaddr) >= 0);
		}

		offset += len_in_blk;
		count -= len_in_blk;
		buffer += len_in_blk;
		written_count += len_in_blk;

		dn.ofs_in_node++;
		if ((--remained_blkentries == 0 || count == 0) && (dn.ndirty))
			ASSERT(dev_write_block(dn.node_blk, dn.node_blkaddr) >= 0);
	}
	if (offset > le64_to_cpu(inode->i.i_size)) {
		inode->i.i_size = cpu_to_le64(offset);
		idirty = 1;
	}
	if (idirty) {
		ASSERT(inode == dn.inode_blk);
		write_inode(ni.blk_addr, inode);
	}
	if (index_node)
		free(index_node);
	free(blk_buffer);

	return written_count;
}

/* This function updates only inode->i.i_size */
void f2fs_filesize_update(struct f2fs_sb_info *sbi, nid_t ino, u64 filesize)
{
	struct node_info ni;
	struct f2fs_node *inode;

	inode = calloc(BLOCK_SZ, 1);
	ASSERT(inode);
	get_node_info(sbi, ino, &ni);

	ASSERT(dev_read_block(inode, ni.blk_addr) >= 0);
	ASSERT(!S_ISDIR(le16_to_cpu(inode->i.i_mode)));
	ASSERT(!S_ISLNK(le16_to_cpu(inode->i.i_mode)));

	inode->i.i_size = cpu_to_le64(filesize);

	write_inode(ni.blk_addr, inode);
	free(inode);
}

int f2fs_build_file(struct f2fs_sb_info *sbi, struct dentry *de)
{
	int fd, n;
	pgoff_t off = 0;
	u8 buffer[BLOCK_SZ];

	if (de->ino == 0)
		return -1;

	fd = open(de->full_path, O_RDONLY);
	if (fd < 0) {
		MSG(0, "Skip: Fail to open %s\n", de->full_path);
		return -1;
	}

	/* inline_data support */
	if (de->size <= DEF_MAX_INLINE_DATA) {
		struct node_info ni;
		struct f2fs_node *node_blk;
		int ret;

		get_node_info(sbi, de->ino, &ni);

		node_blk = calloc(BLOCK_SZ, 1);
		ASSERT(node_blk);

		ret = dev_read_block(node_blk, ni.blk_addr);
		ASSERT(ret >= 0);

		node_blk->i.i_inline |= F2FS_INLINE_DATA;
		node_blk->i.i_inline |= F2FS_DATA_EXIST;

		if (c.feature & cpu_to_le32(F2FS_FEATURE_EXTRA_ATTR)) {
			node_blk->i.i_inline |= F2FS_EXTRA_ATTR;
			node_blk->i.i_extra_isize =
				cpu_to_le16(F2FS_TOTAL_EXTRA_ATTR_SIZE);
		}
		n = read(fd, buffer, BLOCK_SZ);
		ASSERT((unsigned long)n == de->size);
		memcpy(inline_data_addr(node_blk), buffer, de->size);
		node_blk->i.i_size = cpu_to_le64(de->size);
		write_inode(ni.blk_addr, node_blk);
		free(node_blk);
	} else {
		while ((n = read(fd, buffer, BLOCK_SZ)) > 0) {
			f2fs_write(sbi, de->ino, buffer, n, off);
			off += n;
		}
	}

	close(fd);
	if (n < 0)
		return -1;

	update_free_segments(sbi);

	MSG(1, "Info: Create %s -> %s\n"
		"  -- ino=%x, type=%x, mode=%x, uid=%x, "
		"gid=%x, cap=%"PRIx64", size=%lu, pino=%x\n",
		de->full_path, de->path,
		de->ino, de->file_type, de->mode,
		de->uid, de->gid, de->capabilities, de->size, de->pino);
	return 0;
}
