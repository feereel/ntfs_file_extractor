#include "ntfs.h"

#define SEARCH_FILENAME "FORTASK"
#define OUTPUT_FILENAME "FORTASK"

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

void fix_markups(FILE* disk, record file_record, int64_t file_record_addr){
    uint16_t markers[file_record.markerarr_len];

    fseek(disk, file_record_addr + file_record.markers_offset, SEEK_SET);
    if (fread(markers, sizeof(uint16_t) * file_record.markerarr_len, 1,disk) < 0){perror("fread attribute"); exit(__LINE__);}

    // printf("file_record_addr: %llu\n", file_record_addr);
    // printf("markers: %hu\n", (uint16_t)(*markers));
    for (size_t i = 1; i <= FILE_RECORD_SIZE/FILE_RECORD_MARKUP_OFFSET; i ++){
        fseek(disk, file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2, SEEK_SET);
        if (fwrite(&markers[i], sizeof(uint16_t), 1,disk) < 0){perror("fread attribute"); exit(__LINE__);}
        // printf("markers[i]: %hu writed to addr: %llu\n", markers[i], file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2);
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
        fix_markups(disk, file_record, mft_addr);

        if (find_name_attribute(disk, file_record, mft_addr, filename) >= 0 &&\
            (data_attr_addr = find_data_attribute(disk, file_record, mft_addr)) >= 0){
            
            // printf("data_attr_addr: %llu\n", data_attr_addr);
            return data_attr_addr;
        }
        mft_addr += FILE_RECORD_SIZE;
    }
    return -1;
}

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

int main(int argc, char* argv[]){
    FILE *disk, *out;
    bootsec boot_sector;

    if (argc != 2){perror("argv"); exit(__LINE__);}
    if ((disk = fopen(argv[1], "r+")) == NULL){perror("fopen disk"); exit(__LINE__);}
    if (fread(&boot_sector, sizeof(bootsec), 1,disk) <= 0){perror("fread boot_sector"); exit(__LINE__);}

    int64_t mft_addr = boot_sector.sector_size * boot_sector.cluster_size * boot_sector.MFT_addr;

    // printf("mft_addr: %llu\n", mft_addr);

    int64_t data_attr_addr = get_rdata_by_name(disk, mft_addr, SEARCH_FILENAME);

    if ((out = fopen(OUTPUT_FILENAME, "w")) == NULL){perror("fopen output file"); exit(__LINE__);}

    extract_file(disk, data_attr_addr, out);

    fclose(disk);
    fclose(out);
}

