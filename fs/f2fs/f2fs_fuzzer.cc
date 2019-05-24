#include <iostream>
#include <algorithm>
#include <set>
#include <string>
#include <memory>
#include <stdexcept>
#include <array>

#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "f2fs_fuzzer.hh"
#include "utils.hh"

/*
 * CRC32
 */
#define CRCPOLY_LE 0xedb88320

uint32_t f2fs_cal_crc32(uint32_t crc, void *buf, int len)
{
	int i;
	unsigned char *p = (unsigned char *)buf;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}

void f2fs_fuzzer::fix_checksum() 
{
	uint32_t calc_crc;

	calc_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, (char *)image_buffer_ + cp1_page1_off,
										cp1_page1_crc);
	*(uint32_t *)((char *)image_buffer_ + cp1_page1_off + cp1_page1_crc) = calc_crc;

	calc_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, (char *)image_buffer_ + cp1_page2_off,
										cp1_page2_crc);
	*(uint32_t *)((char *)image_buffer_ + cp1_page2_off + cp1_page2_crc) = calc_crc;

	calc_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, (char *)image_buffer_ + cp2_page1_off,
										cp2_page1_crc);
	*(uint32_t *)((char *)image_buffer_ + cp2_page1_off + cp2_page1_crc) = calc_crc;

	calc_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, (char *)image_buffer_ + cp2_page2_off,
										cp2_page2_crc);
	*(uint32_t *)((char *)image_buffer_ + cp2_page2_off + cp2_page2_crc) = calc_crc;

}

void f2fs_fuzzer::fix_general_checksum()
{
}

void f2fs_fuzzer::add_superblock()
{
    memcpy(&sb, (char *)image_buffer_ + F2FS_SUPER_OFFSET, sizeof(struct f2fs_super_block));

    block_size_ = 1 << sb.log_blocksize;
	printf("block size: 0x%x\n", block_size_);
	segment_size_ = block_size_ * (1 << sb.log_blocks_per_seg);
	printf("segment size: 0x%lx\n", segment_size_);
    
	sb1_off = F2FS_SUPER_OFFSET;
    meta_offsets.insert(sb1_off); /* SP1 */
	sb2_off = sb1_off + block_size_;
    meta_offsets.insert(sb2_off); /* SP2 */

}

void f2fs_fuzzer::add_checkpoint()
{
	uint64_t cp_addr = sb.cp_blkaddr;
	struct f2fs_checkpoint *cp;

	cp1_page1_off = blk2off(cp_addr);
	cp = (struct f2fs_checkpoint *)((char *)image_buffer_ + cp1_page1_off);
	cp1_page1_crc = cp->checksum_offset;
	printf("cp1 page1: 0x%lx crc offset: 0x%lx\n", cp1_page1_off, cp1_page1_crc);

	for (uint64_t i = 0; i < 1 + sb.cp_payload; i++)
		meta_offsets.insert(blk2off(cp_addr + i));

	cp1_page2_off = blk2off(cp_addr + cp->cp_pack_total_block_count - 1);
	cp = (struct f2fs_checkpoint *)((char *)image_buffer_ + cp1_page2_off);
	cp1_page2_crc = cp->checksum_offset;
	printf("cp1 page2: 0x%lx crc offset: 0x%lx\n", cp1_page2_off, cp1_page2_crc);
	meta_offsets.insert(cp1_page2_off);

	cp_addr = sb.cp_blkaddr + (1 << sb.log_blocks_per_seg);
	cp2_page1_off = blk2off(cp_addr);
	cp = (struct f2fs_checkpoint *)((char *)image_buffer_ + cp2_page1_off);
	cp2_page1_crc = cp->checksum_offset;
	printf("cp2 page1: 0x%lx crc offset: 0x%lx\n", cp2_page1_off, cp2_page1_crc);

	for (uint64_t i = 0; i < 1 + sb.cp_payload; i++)
		meta_offsets.insert(blk2off(cp_addr + i));

	cp2_page2_off = blk2off(cp_addr + cp->cp_pack_total_block_count - 1);
	cp = (struct f2fs_checkpoint *)((char *)image_buffer_ + cp2_page2_off);
	cp2_page2_crc = cp->checksum_offset;
	printf("cp2 page2: 0x%lx crc offset: 0x%lx\n", cp2_page2_off, cp2_page2_crc);
	meta_offsets.insert(cp2_page2_off);
}

void f2fs_fuzzer::add_sit()
{
	uint64_t sit_addr = sb.sit_blkaddr;
	uint64_t sit_block_nr = (sb.segment_count_sit  / 2) * segment_size_ / block_size_;
	printf("sit: 0x%lx count: 0x%lx\n", sit_addr, sit_block_nr);
	for (uint64_t i = 0; i < std::min(uint64_t(2), (sb.segment_count_sit  / 2) * segment_size_ / block_size_); i++)
		meta_offsets.insert(blk2off(sit_addr + i));
}

void f2fs_fuzzer::add_nat()
{
	uint64_t nat_addr = sb.nat_blkaddr;
	uint64_t nat_block_nr = (sb.segment_count_nat  / 2) * segment_size_ / block_size_;
	printf("nat: 0x%lx count: 0x%lx\n", nat_addr, nat_block_nr);
	for (uint64_t i = 0; i < std::min(uint64_t(2), nat_block_nr); i++)
		meta_offsets.insert(blk2off(nat_addr + i));
}

void f2fs_fuzzer::add_ssa()
{
	uint64_t ssa_addr = sb.ssa_blkaddr;
	uint64_t ssa_block_nr = sb.segment_count_ssa * segment_size_ / block_size_;
	printf("ssa: 0x%lx count: 0x%lx\n", ssa_addr, ssa_block_nr);
	for (uint64_t i = 0; i < std::min(uint64_t(2), ssa_block_nr); i++)
		meta_offsets.insert(blk2off(ssa_addr + i));
}

void f2fs_fuzzer::add_main(const char *in_path)
{
	uint64_t main_addr = sb.main_blkaddr;
	uint64_t main_block_nr = sb.segment_count_main * segment_size_ / block_size_;
	printf("main: 0x%lx count: 0x%lx\n", main_addr, main_block_nr);

	char cmd[128];
	sprintf(cmd, "dump.f2fs -f %s", in_path);

	std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
	std::string needle("Block_addr: ");
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr) {
            result = buffer.data();
			std::size_t pos = result.find(needle);
			if (pos != std::string::npos) {
				std::string block_nr_str = result.substr(pos + needle.length());
				uint64_t block_nr = std::stoll(block_nr_str);
				printf("main block: 0x%lx\n", block_nr);
				meta_offsets.insert(blk2off(block_nr));
			}
		}
    }
}

void f2fs_fuzzer::compress(
        const char *in_path,
        void *buffer,
        const char *meta_path)
{
    bool generate_meta_image = meta_path != NULL;

    struct stat st;
    stat(in_path, &st);

    image_size_ = st.st_size;

    int in_image_fd = open(in_path, O_RDONLY);
    if (in_image_fd < 0)
        FATAL("[-] image %s compression failed.", in_path);

    image_buffer_ = buffer;
    if (read(in_image_fd, image_buffer_, image_size_) != image_size_)
        FATAL("[-] image %s compression failed.", in_path);

    close(in_image_fd);

    add_superblock();
    add_checkpoint(); 
	add_sit();	
	add_nat();
	add_ssa();
	add_main(in_path);

	int meta_image_fd = -1;
  	if (generate_meta_image) {
    	meta_image_fd = open(meta_path, O_CREAT | O_RDWR | O_TRUNC, 0666);
    	if (meta_image_fd < 0)
      		FATAL("[-] image %s compression failed.", in_path);
  	}

	if (!release_metadata(meta_offsets, meta_image_fd, false)) 
    	FATAL("[-] image %s compression failed.", in_path);

  	if (generate_meta_image)
    	close(meta_image_fd);

  	print_metadata();

}

void f2fs_fuzzer::decompress(
    const void *meta_buffer,
    size_t meta_len,
    bool checksum) {

 	size_t meta_offset = 0;

  	for (extent_t &extent : metadata_) {
    	memcpy((char *)image_buffer_ + extent.first,
        	(char *)meta_buffer + meta_offset, extent.second);
    	meta_offset += extent.second;
  	}
  
  	if (checksum)
    	fix_checksum();
}

void f2fs_fuzzer::general_decompress(
    const void *meta_buffer,
    size_t meta_len,
    bool checksum) {

 	size_t meta_offset = 0;

  	for (extent_t &extent : metadata_) {
    	memcpy((char *)image_buffer_ + extent.first,
        	(char *)meta_buffer + meta_offset, extent.second);
    	meta_offset += extent.second;
  	}
  
  	if (checksum)
    	fix_general_checksum();
}
