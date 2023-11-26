#include "ntfs.h"

#define SEARCH_FILENAME "FORTASK"
// #define SEARCH_FILENAME "najkintxc"
#define OUTPUT_FILENAME "FORTASK"

int64_t extract_file(uint8_t* disk, FILE* out, range* data_ranges, size_t data_range_size, int64_t total_data_size){
    int64_t readed = 0;
    for (size_t i = 0; i < data_range_size; i++){
        for (size_t j = 0; j < data_ranges[i].end; j++){
            fputc(disk[data_ranges[0].start + j], out);
            if(++readed == total_data_size){
                return readed;
            }
        }
    }
    return readed;
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

int compare_names(uint8_t *disk, int64_t filename_attr_addr, char filename[]){
    uint8_t name_len = *(uint8_t*)(disk + filename_attr_addr + 0x40);

	char name[name_len + 1];
    
    for(int i = 0; i < name_len; i++){
        name[i] = *(char*)(disk + filename_attr_addr + 0x42 + i*2);
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

int64_t find_attribute(uint8_t* disk, int64_t* attr_addr, int64_t last_attr_addr, int file_record_id, attribute *attr){
    //printf("*attr_addr: %llu, last_attr_addr: %llu\n", *attr_addr, last_attr_addr);

    attribute _attr = *attr;
    while (*attr_addr < last_attr_addr){
        _attr = *(attribute*)(disk + *attr_addr);

        *attr_addr += _attr.length;

        //printf("attr.length: %u\n", _attr.length);
        //printf("attr.id: %u\n", _attr.id);

        if (_attr.id == END_SIGNATURE || _attr.length == 0) break;

        if (_attr.id == file_record_id){
            *attr = _attr;
            return *attr_addr - _attr.length;
        }
    }
    return -1;
}

int64_t find_name_attribute(uint8_t* disk, record file_record, int64_t file_record_addr, char filename[]){
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
int64_t find_data_attribute(uint8_t* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, DATA_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

int64_t find_iroot_attribute(uint8_t* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, IROOT_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

int64_t find_iallocation_attribute(uint8_t* disk, record file_record, int64_t file_record_addr){
    int64_t next_attr_addr = file_record_addr + file_record.attr_offset;
    int64_t last_attr_addr = file_record_addr + FILE_RECORD_SIZE;
    int64_t name_attr_addr;
    attribute filename_attr;

    while ((name_attr_addr = find_attribute(disk, &next_attr_addr, last_attr_addr, IALLOCATION_ID, &filename_attr)) > 0){
        return name_attr_addr;
    }
    return -1;
}

void fix_record_markups(uint8_t* disk, record file_record, int64_t file_record_addr){
    uint16_t markers[file_record.markerarr_len];

    memcpy(markers, disk, 2 * file_record.markerarr_len);

    // printf("file_record_addr: %llu\n", file_record_addr);
    // printf("markers: %hu\n", (uint16_t)(*markers));
    for (size_t i = 1; i <= FILE_RECORD_SIZE/FILE_RECORD_MARKUP_OFFSET; i++){
        markers[i] = *(uint16_t*)(disk + file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2);
        // printf("markers[i]: %hu writed to addr: %llu\n", markers[i], file_record_addr + (i * FILE_RECORD_MARKUP_OFFSET) - 2);
    }
}

// +
void fix_irecord_markups(uint8_t* disk, irecord_header indx_header, range indx_range){
    uint16_t markers[indx_header.markerarr_len];
    size_t size = indx_range.end - indx_range.start; 

    // printf("indx_range.start: %llx, indx_header.marker_offset: %hx\n", indx_range.start, indx_header.marker_offset);

    memcpy(markers, disk, 2 * indx_header.markerarr_len);

    // printf("size: %zx IRECORD_MARKUP_OFFSET: %x\n", size, IRECORD_MARKUP_OFFSET);
    for (size_t i = 1; i <= size/IRECORD_MARKUP_OFFSET; i++){
        markers[i] = *(uint16_t*)(disk + indx_range.start + (i * IRECORD_MARKUP_OFFSET) - 2);
        // printf("markers[%zu]: %hx writed to addr: %llx\n", i, markers[i], indx_range.start + (i * IRECORD_MARKUP_OFFSET) - 2);
    }
}

uint8_t* get_drun_from_attr(uint8_t* disk, attribute attr, int64_t attr_addr, size_t* drun_size){
    int64_t drun_offset;
    uint8_t *drun;

    drun_offset = *(int64_t*)(disk + attr_addr + 0x20);
    *drun_size = attr.length - drun_offset;

    printf("drun_size: %zu\n", *drun_size);

    drun = malloc(sizeof(uint8_t) * (*drun_size));

    printf("attr_addr + drun_offset: %llx\n", attr_addr + drun_offset);
    memcpy(drun, disk + attr_addr + drun_offset, *drun_size);
    printf("(int64_t)(*drun): %llx\n", *(int64_t*)(drun));

    return drun;
}

/// @brief get data from file by record
/// @param disk 
/// @param mft_addr 
/// @param filename 
/// @return returns ranges where data is stored. if error happend return NULL
range* get_data_range_by_record(uint8_t* disk, record file_record, int64_t file_record_addr, size_t* range_size, int64_t *total_data_size){
    range *data_attr_range = NULL;
    int64_t data_attr_addr, _total_data_size;
    attribute data_attr;

    uint8_t *drun;
    size_t drun_size;
    
    fix_record_markups(disk, file_record, file_record_addr);

    if ((data_attr_addr = find_data_attribute(disk, file_record, file_record_addr)) < 0) return NULL;
    
    printf("data_attr_addr: %llx\n", data_attr_addr);

    data_attr = *(attribute*)(disk + data_attr_addr);

    if(data_attr.non_resident_flag){
        drun = get_drun_from_attr(disk, data_attr, data_attr_addr, &drun_size);
        data_attr_range = drun_to_ranges(drun, drun_size, range_size);
        printf("data attribute is not resident\n");

        _total_data_size = *(int64_t*)(disk + data_attr_addr + 0x38);

        free(drun);
    } else {
        data_attr_range = malloc(sizeof(range));
        data_attr_range[0].start = data_attr_addr + data_attr.data_offset;
        data_attr_range[0].end = data_attr_range[0].start + data_attr.data_size;
        _total_data_size = data_attr.data_size;
        *range_size = 1;
        printf("data attribute is resident\n");
    }
    *total_data_size = _total_data_size;
    return data_attr_range;
}

int64_t find_directory(uint8_t* disk, record file_record, int64_t file_record_addr){
    int64_t dir_attr_addr;
    attribute dir_attr;
    if((dir_attr_addr = find_iroot_attribute(disk, file_record, file_record_addr)) > 0){
        dir_attr = *(attribute*)(disk + dir_attr_addr);

        // printf("dir_attr_addr + dir_attr.data_offset + 0x2a: %llu\n", dir_attr_addr + dir_attr.data_offset + 0x2a);
        uint16_t S = *(uint16_t*)(disk + dir_attr_addr + dir_attr.data_offset + 0x2a);
        // printf("S: %hu\n", S);
        if (S != 0) return dir_attr_addr;
    }
    if((dir_attr_addr = find_iallocation_attribute(disk, file_record, file_record_addr)) > 0)
        return dir_attr_addr;
    return -1;
}

int64_t find_ientry(uint8_t* disk, range ientries_range[], size_t size, char* filename){
    ientry_header ientry;
    ientry.ientry_length = 1;
    for (size_t i = 0; i < size; i++){
        int64_t next_ientry = ientries_range[i].start;
        // printf("next_ientry: %llx, end: %llx\n", next_ientry, ientries_range[i].end);
        while(next_ientry < ientries_range[i].end && ientry.ientry_length > 0){
            // printf("next_ientry: %llx\n", next_ientry);
            ientry = *(ientry_header*)(disk + next_ientry);

            if (compare_names(disk, next_ientry + 0x10, filename))
                return ientry.file_reference & 0xffffffffffff;

            next_ientry += ientry.ientry_length;
        }
    }
    return -1;
}

int64_t find_inode_in_iroot(uint8_t* disk, attribute iroot_attr, int64_t iroot_attr_addr, char* filename){
    iroot_header iroot;
    range ientries_range[1];

    iroot = *(iroot_header*)(disk + iroot_attr_addr + iroot_attr.data_offset);

    ientries_range[0].start = iroot_attr_addr + iroot_attr.data_offset + 0x10 + iroot.inode.first_ientry_offset;
    ientries_range[0].end = iroot_attr_addr + iroot_attr.length;

    // printf("ientries_range[0].start: %llx, ientries_range[0].end: %llx\n", ientries_range[0].start, ientries_range[0].end);

    return find_ientry(disk, ientries_range, 1, filename);
}

int64_t find_inode_in_ialloc(uint8_t* disk, attribute ialloc_attr, int64_t ialloc_attr_addr, char* filename){
    uint8_t *drun;
    range *indx_ranges;
    size_t drun_size, range_size;

    drun = get_drun_from_attr(disk, ialloc_attr, ialloc_attr_addr, &drun_size);

    indx_ranges = drun_to_ranges(drun, drun_size, &range_size);

    irecord_header irecord;
    for (size_t i = 0; i < range_size; i++){
        irecord = *(irecord_header*)(disk + indx_ranges[i].start);

        fix_irecord_markups(disk, irecord, indx_ranges[i]);
        indx_ranges[i].start += irecord.inode.first_ientry_offset + 0x18;
    }
    // printf("indx_ranges[0].start: %llx, indx_ranges[0].end: %llx\n", indx_ranges[0].start, indx_ranges[0].end);
    return find_ientry(disk, indx_ranges, 1, filename);

    free(indx_ranges);
    free(drun);
}

int64_t find_file_by_name(uint8_t* disk, int64_t mft_addr, char* filename){

    record file_record;
    attribute dir_attr;
    int64_t dir_attr_addr;
    int64_t file_addr = mft_addr + FILE_RECORD_SIZE * ROOT_RECORD_ID;

    // printf("root_addr: %llu\n", file_addr);

    file_record = *(record*)(disk+file_addr);

    if((dir_attr_addr = find_directory(disk, file_record, file_addr)) < 0){
        // CAN RETURN -1 IF ITS FILE
        return -1;
    }

    printf("dir_attr_addr: %llu\n", dir_attr_addr);

    dir_attr = *(attribute*)(disk + dir_attr_addr);

    if (dir_attr.id == IROOT_ID){
        return find_inode_in_iroot(disk, dir_attr, dir_attr_addr, filename);
    } else if (dir_attr.id == IALLOCATION_ID){
        return find_inode_in_ialloc(disk, dir_attr, dir_attr_addr, filename);
    }
    return -1;
}

int main(int argc, char* argv[]){
    int fd_disk;
    uint8_t *disk;
    struct stat statbuf;

    record file_record;
    range* data_ranges;
    int64_t mft_addr, file_record_id, file_record_addr, total_data_size;
    size_t data_range_size;

    FILE* out;

    if (argc != 2){perror("argv"); exit(__LINE__);}

    if ((fd_disk = open(argv[1], O_RDWR)) < 0 ){perror("fopen disk"); exit(__LINE__);}

    if (fstat(fd_disk, &statbuf) < 0 ){perror("fstat disk"); exit(__LINE__);}

    printf("%lld\n", statbuf.st_size);

    if ((disk = mmap(NULL, statbuf.st_size * sizeof(uint8_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd_disk, 0)) == MAP_FAILED )
        {perror("mmap disk"); exit(__LINE__);}

    printf("%hhx %hhx %hhx\n", disk[0], disk[1], disk[2]);

    boot_sector = *(bootsec*)(disk);
    mft_addr = boot_sector.sector_size * boot_sector.cluster_size * boot_sector.MFT_addr;

    printf("mft_addr %llu\n", mft_addr);

    file_record_id = find_file_by_name(disk, mft_addr, SEARCH_FILENAME);
    printf("find_file_by_name: %llu\n", file_record_id);

    file_record_addr = mft_addr + file_record_id * FILE_RECORD_SIZE;

    file_record = *(record*)(disk + file_record_addr);

    data_ranges = get_data_range_by_record(disk, file_record, file_record_addr, &data_range_size, &total_data_size);
    printf("data_attr_range[0].start: %llx, data_attr_range[0].end: %llx\n", data_ranges[0].start, data_ranges[0].end);
    printf("total_data_size: %llx\n", total_data_size);
    printf("data_range_size: %zu\n", data_range_size);

    if ((out = fopen(OUTPUT_FILENAME, "w")) == NULL){perror("fopen outfile"); exit(__LINE__);}

    printf("total_readed: %llx\n", extract_file(disk, out, data_ranges, data_range_size, total_data_size));

    free(data_ranges);
    close(fd_disk);
}

