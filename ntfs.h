#ifndef _NTFS_
#define _NTFS_

#include <stdio.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>

#include <fcntl.h>
#include <unistd.h>
#include<sys/mman.h>
#include <sys/stat.h>

#define FILE_RECORD_SIZE 1024
#define FILE_RECORD_MARKUP_OFFSET 0x200
#define IRECORD_MARKUP_OFFSET 0x400

#define FILENAME_ID 0x30
#define DATA_ID 0x80
#define IROOT_ID 0x90
#define IALLOCATION_ID 0xA0

#define ROOT_RECORD_ID 5

#define END_SIGNATURE 0xffffffff

#ifdef DEBUG
#define dprintf(fmt,...) printf(fmt, __VA_ARGS__)
#else
#define dprintf(fmt,...)
#endif


typedef struct boot_sector{
	uint8_t skip[11];
	uint16_t sector_size;
	uint8_t cluster_size;
	uint16_t reserved;
	uint8_t notused[8];
	uint16_t sectors_per_track;
	uint16_t num_of_heads;
	uint32_t hidden_sec;
	uint8_t not_used[16];
	uint64_t MFT_addr;
} __attribute__((packed)) bootsec;

typedef struct record{
	uint8_t signature[4];
	uint16_t markers_offset;
	uint16_t markerarr_len;
	uint8_t numtran[8];
	uint16_t number;
	uint16_t counter;
	uint16_t attr_offset;
	uint8_t flags;
	uint32_t record_real_size;
	uint32_t record_allocated_size;
} __attribute__((packed)) record;

typedef struct attribute{
	uint32_t id;
	uint32_t length;
	uint8_t non_resident_flag;
	uint8_t name_length;
	uint16_t name_offset;
	uint16_t flags;
	uint16_t attr_id;
	uint32_t data_size;
	uint16_t data_offset;
} __attribute__((packed)) attribute;

typedef struct inode_header{
	uint32_t first_ientry_offset;
	uint32_t size;
	uint32_t allocated_size;
	uint8_t nonleaf_flag;
	uint8_t empty[3];
} __attribute__((packed)) inode_header;

typedef struct iroot_header{
	uint32_t id;
	uint32_t collation_rule;
	uint32_t irecord_size;
	uint8_t irecord_cluster_size;
	uint8_t empty[3];
	inode_header inode;
} __attribute__((packed)) iroot_header;

typedef struct ientry_header{
	uint64_t file_reference;
	uint16_t ientry_length;
	uint16_t stream_length;
	uint8_t flags;
	uint8_t empty[3];
} __attribute__((packed)) ientry_header;

typedef struct range{
	int64_t start;
	int64_t end;
} range;

typedef struct irecord_header{
	uint32_t magic;
	uint16_t marker_offset;
	uint16_t markerarr_len;
	uint64_t log_file_marker;
	uint64_t vcn;
	inode_header inode;
} __attribute__((packed)) irecord_header;

bootsec boot_sector;

#endif
