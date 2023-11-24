#ifndef _NTFS_
#define _NTFS_

#include <stdio.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>

#define FILE_RECORD_SIZE 1024
#define FILE_RECORD_MARKUP_OFFSET 0x200

#define FILENAME_ID 0x30
#define DATA_ID 0x80

#define END_SIGNATURE 0xffffffff

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

#endif
