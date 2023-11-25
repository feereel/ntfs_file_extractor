#include "ntfs.h"

#define SEARCH_FILENAME "FORTASK"
#define OUTPUT_FILENAME "FORTASK"

int extract_file(FILE* disk, int64_t data_attr_addr, FILE* out){
    fseek(disk, data_attr_addr, SEEK_SET);

    attribute data_attr;
    if (fread(&data_attr, sizeof(attribute), 1,disk) <= 0){perror("read data_attr"); exit(__LINE__);}

    fseek(disk, data_attr_addr + data_attr.data_offset, SEEK_SET);

    // printf("data_attr_addr + data_attr.data_offset: %llu\n", data_attr_addr + data_attr.data_offset);

    char ch;
    size_t i;
    for (i = 0; i < data_attr.data_size; i++){
        ch = fgetc(disk);
        fputc(ch, out);
    }
    return i;
}

range* drun_to_ranges(uint8_t *drun, size_t drun_size, size_t *range_size){
    size_t i = 0, length = 0, offset = 0;

    range *ientries_range = malloc(0);
    size_t _range_size = 0;

    while (i < drun_size){
        length = drun[i] & 0xf;
        offset = drun[i] >> 4;

        // printf("drun[i]: %hhx lenght: %zu, offset: %zu\n", drun[i], length, offset);

        ientries_range = realloc(ientries_range, sizeof(range)*(++_range_size));

        memcpy(&ientries_range[_range_size-1].start, drun + i + length + 1, offset);
        memcpy(&ientries_range[_range_size-1].end, drun + i + 1, length);
        ientries_range[_range_size-1].end += ientries_range[_range_size-1].start;

        ientries_range[_range_size-1].start *= boot_sector.sector_size * boot_sector.cluster_size;
        ientries_range[_range_size-1].end *= boot_sector.sector_size * boot_sector.cluster_size;

        // printf("ientries_range[%zu]: start: %llx, end: %llx\n", _range_size-1, ientries_range[_range_size-1].start, ientries_range[_range_size-1].end);

        i += length + offset + 1;
    }
    *range_size = _range_size;
    return ientries_range;
}

int compare_names(FILE* disk, int64_t filename_attr_addr, char filename[]){
    fseek(disk, filename_attr_addr + 0x40, SEEK_SET);
    uint8_t name_len;
	if(fread(&name_len, sizeof(uint8_t), 1, disk) != 1){perror("fread length of file name");exit(__LINE__);}

	char name[name_len + 1];
    char buff[2];
    
    fseek(disk, filename_attr_addr + 0x42, SEEK_SET);
    for(int i = 0; i < name_len; i++){
	    if(fread(buff, sizeof(buff), 1, disk) != 1){perror("fread file name");exit(__LINE__);}
        name[i] = buff[0];
    }
    name[name_len] = '\0';

    // printf("name_len: %hhu\n", name_len);
    // printf("buff: %s\n", buff);
    // printf("name: %s\n", name);
    // printf("filename: %s\n", filename);
    
    if(!strcmp(filename, name)){
        return 1;
    }
    return 0;
}

int64_t find_attribute(FILE* disk, int64_t* attr_addr, int64_t last_attr_addr, int file_record_id, attribute *attr){
    //printf("*attr_addr: %llu, last_attr_addr: %llu\n", *attr_addr, last_attr_addr);
    while (*attr_addr < last_attr_addr){
        fseek(disk, *attr_addr, SEEK_SET);
        if (fread(attr, sizeof(attribute), 1,disk) <= 0){perror("fread attribute"); exit(__LINE__);}
        *attr_addr += attr->length;

        //printf("attr.length: %u\n", attr->length);
        //printf("attr.id: %u\n", attr->id);

        if (attr->id == END_SIGNATURE || attr->length == 0) break;

        if (attr->id == file_record_id)
            return *attr_addr - attr->length;
    }
    return -1;
}

int64_t find_name_attribute(FILE* disk, record file_record, int64_t file_record_addr, char filename[]){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, FILENAME_ID, &filename_attr)) > 0){
        // printf("name_attr_addr: %llu\n", name_attr_addr + filename_attr.data_offset);
        if (compare_names(disk, name_attr_addr + filename_attr.data_offset, filename)){
            return name_attr_addr;
        }
    }
    return -1;
}

// TODO: ADD search by thread_name
int64_t find_data_attribute(FILE* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, DATA_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

int64_t find_iroot_attribute(FILE* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, IROOT_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

int64_t find_iallocation_attribute(FILE* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, IALLOCATION_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

void fix_record_markups(FILE* disk, record file_record, int64_t file_record_addr){
    uint16_t markers[file_record.markerarr_len];

    fseek(disk, file_record_addr + file_record.markers_offset, SEEK_SET);
    if (fread(markers, sizeof(uint16_t) * file_record.markerarr_len, 1,disk) < 0){perror("fread attribute"); exit(__LINE__);}

    // printf("file_record_addr: %llu\n", file_record_addr);
    // printf("markers: %hu\n", (uint16_t)(*markers));
    for (size_t i = 1; i <= FILE_RECORD_SIZE/FILE_RECORD_MARKUP_OFFSET; i++){
        fseek(disk, file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2, SEEK_SET);
        if (fwrite(&markers[i], sizeof(uint16_t), 1,disk) < 0){perror("fread attribute"); exit(__LINE__);}
        // printf("markers[i]: %hu writed to addr: %llu\n", markers[i], file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2);
    }
}

void fix_irecord_markups(FILE* disk, irecord_header indx_header, range indx_range){
    uint16_t markers[indx_header.markerarr_len];
    size_t size = indx_range.end - indx_range.start; 

    fseek(disk, indx_range.start + indx_header.marker_offset, SEEK_SET);

    // printf("indx_range.start: %llx, indx_header.marker_offset: %hx\n", indx_range.start, indx_header.marker_offset);
    if (fread(markers, sizeof(uint16_t), indx_header.markerarr_len, disk) < 0){perror("fread attribute"); exit(__LINE__);}

    // printf("size: %zx IRECORD_MARKUP_OFFSET: %x\n", size, IRECORD_MARKUP_OFFSET);
    for (size_t i = 1; i <= size/IRECORD_MARKUP_OFFSET; i++){
        fseek(disk, indx_range.start + (i * IRECORD_MARKUP_OFFSET) - 2, SEEK_SET);
        if (fwrite(&markers[i], sizeof(uint16_t), 1,disk) < 0){perror("fread markers (fix_irecord_markups)"); exit(__LINE__);}
        // printf("markers[%zu]: %hx writed to addr: %llx\n", i, markers[i], indx_range.start + (i * IRECORD_MARKUP_OFFSET) - 2);
    }
}

/// @brief get data from resident file by file name
/// @param disk 
/// @param mft_addr 
/// @param filename 
/// @return returns data attribute address what contains file data
int64_t get_rdata_by_name(FILE* disk, int64_t mft_addr, char filename[]){
    record file_record;
    int64_t data_attr_addr;

    while(1){ // TODO: FIX! may cause an infinite loop
        fseek(disk, mft_addr, SEEK_SET);
        if (fread(&file_record, sizeof(record), 1,disk) <= 0){perror("fread file_record"); exit(__LINE__);}
        fix_record_markups(disk, file_record, mft_addr);

        if (find_name_attribute(disk, file_record, mft_addr, filename) >= 0 &&\
            (data_attr_addr = find_data_attribute(disk, file_record, mft_addr)) >= 0){
            
            // printf("data_attr_addr: %llu\n", data_attr_addr);
            return data_attr_addr;
        }
        mft_addr += FILE_RECORD_SIZE;
    }
    return -1;
}

int64_t find_directory(FILE* disk, record file_record, int64_t file_record_addr){
    int64_t dir_attr_addr;
    attribute dir_attr;
    if((dir_attr_addr = find_iroot_attribute(disk, file_record, file_record_addr)) > 0){
        fseek(disk, dir_attr_addr, SEEK_SET);
        if (fread(&dir_attr, sizeof(attribute), 1,disk) < 0){perror("fread attribute (find_directory)"); exit(__LINE__);}

        fseek(disk, dir_attr_addr + dir_attr.data_offset + 0x2a, SEEK_SET);

        // printf("dir_attr_addr + dir_attr.data_offset + 0x2a: %llu\n", dir_attr_addr + dir_attr.data_offset + 0x2a);
        uint16_t S;
        if (fread(&S, sizeof(uint16_t), 1,disk) < 0){perror("fread S (find_directory)"); exit(__LINE__);}
        // printf("S: %hu\n", S);
        if (S != 0) return dir_attr_addr;
    }
    if((dir_attr_addr = find_iallocation_attribute(disk, file_record, file_record_addr)) > 0)
        return dir_attr_addr;
    return -1;
}

int64_t find_ientry(FILE* disk, range ientries_range[], size_t size, char* filename){
    ientry_header ientry;
    for (size_t i = 0; i < size; i++){
        int64_t next_ientry = ientries_range[i].start;
        // printf("next_ientry: %llx, end: %llx\n", next_ientry, ientries_range[i].end);
        while(next_ientry < ientries_range[i].end && ientry.ientry_length > 0){
            // printf("next_ientry: %llx\n", next_ientry);
            fseek(disk, next_ientry, SEEK_SET);
            if (fread(&ientry, sizeof(ientry_header), 1,disk) <= 0){perror("fread ientry (find_ientry)"); exit(__LINE__);}

            if (compare_names(disk, next_ientry + 0x10, filename))
                return ientry.file_reference & 0xffffffffffff;

            next_ientry += ientry.ientry_length;
        }
    }
    return -1;
}

int64_t find_inode_in_iroot(FILE* disk, attribute iroot_attr, int64_t iroot_attr_addr, char* filename){
    iroot_header iroot;
    range ientries_range[1];

    fseek(disk, iroot_attr_addr + iroot_attr.data_offset, SEEK_SET);
    if (fread(&iroot, sizeof(iroot_header), 1,disk) <= 0){perror("fread record (find_file_by_name)"); exit(__LINE__);}

    ientries_range[0].start = iroot_attr_addr + iroot_attr.data_offset + 0x10 + iroot.inode.first_ientry_offset;
    ientries_range[0].end = iroot_attr_addr + iroot_attr.length;

    // printf("ientries_range[0].start: %llx, ientries_range[0].end: %llx\n", ientries_range[0].start, ientries_range[0].end);

    return find_ientry(disk, ientries_range, 1, filename);
}

int64_t find_inode_in_ialloc(FILE* disk, attribute ialloc_attr, int64_t ialloc_attr_addr, char* filename){
    int64_t drun_offset;
    uint8_t *drun;
    range *indx_ranges;
    size_t drun_size, range_size;

    fseek(disk, ialloc_attr_addr + 0x20, SEEK_SET);
    if (fread(&drun_offset, sizeof(int64_t), 1,disk) <= 0){perror("fread seq_offset (find_inode_in_ialloc)"); exit(__LINE__);}

    drun_size = ialloc_attr.length - drun_offset;
    // printf("drun_size: %zu\n", drun_size);

    drun = malloc(sizeof(uint8_t) * drun_size);

    fseek(disk, ialloc_attr_addr + drun_offset, SEEK_SET);
    if (fread(drun, sizeof(int8_t) * drun_size, 1,disk) <= 0){perror("fread drun (find_inode_in_ialloc)"); exit(__LINE__);}
    // printf("(int64_t)(*drun): %llx\n", *(int64_t*)(drun));

    indx_ranges = drun_to_ranges(drun, drun_size, &range_size);

    irecord_header irecord;
    for (size_t i = 0; i < range_size; i++){
        fseek(disk, indx_ranges[i].start, SEEK_SET);
        if (fread(&irecord, sizeof(irecord), 1,disk) <= 0){perror("fread irecord (find_inode_in_ialloc)"); exit(__LINE__);}
        fix_irecord_markups(disk, irecord, indx_ranges[i]);
        indx_ranges[i].start += irecord.inode.first_ientry_offset + 0x18;
    }
    // printf("indx_ranges[0].start: %llx, indx_ranges[0].end: %llx\n", indx_ranges[0].start, indx_ranges[0].end);

    return find_ientry(disk, indx_ranges, 1, filename);

    free(indx_ranges);
    free(drun);
}

int64_t find_file_by_name(FILE* disk, int64_t mft_addr, char* filename){

    record file_record;
    attribute dir_attr;
    int64_t dir_attr_addr;
    int64_t file_addr = mft_addr + FILE_RECORD_SIZE * ROOT_RECORD_ID;
    int64_t file_record_id;

    // printf("root_addr: %llu\n", file_addr);

    fseek(disk, file_addr, SEEK_SET);
    if (fread(&file_record, sizeof(record), 1,disk) <= 0){perror("fread record (find_file_by_name)"); exit(__LINE__);}
    
    if((dir_attr_addr = find_directory(disk, file_record, file_addr)) < 0){
        // CAN RETURN -1 IF ITS FILE
        return -1;
    }

    // printf("dir_attr_addr: %llu\n", dir_attr_addr);

    fseek(disk, dir_attr_addr, SEEK_SET);
    if (fread(&dir_attr, sizeof(attribute), 1,disk) <= 0){perror("fread dir_attr (find_file_by_name)"); exit(__LINE__);}

    if (dir_attr.id == IROOT_ID){
        // printf("find_inode_in_iroot: %lld\n",find_inode_in_iroot(disk, dir_attr, dir_attr_addr, filename));
        file_record_id = find_inode_in_iroot(disk, dir_attr, dir_attr_addr, filename);
    } else if (dir_attr.id == IALLOCATION_ID){
        // printf("find_inode_in_iroot: %lld\n",find_inode_in_ialloc(disk, dir_attr, dir_attr_addr, filename));
        file_record_id = find_inode_in_ialloc(disk, dir_attr, dir_attr_addr, filename);
    }

    return file_record_id;
}

int main(int argc, char* argv[]){
    FILE *disk;

    if (argc != 2){perror("argv"); exit(__LINE__);}
    if ((disk = fopen(argv[1], "r+")) == NULL){perror("fopen disk"); exit(__LINE__);}
    if (fread(&boot_sector, sizeof(bootsec), 1,disk) <= 0){perror("fread boot_sector"); exit(__LINE__);}

    int64_t mft_addr = boot_sector.sector_size * boot_sector.cluster_size * boot_sector.MFT_addr;

    // printf("mft_addr: %llu\n", mft_addr);

    // int64_t data_attr_addr = get_rdata_by_name(disk, mft_addr, SEARCH_FILENAME);

    // if ((out = fopen(OUTPUT_FILENAME, "w")) == NULL){perror("fopen output file"); exit(__LINE__);}

    // extract_file(disk, data_attr_addr, out);

    find_file_by_name(disk, mft_addr, SEARCH_FILENAME);

    fclose(disk);
}

