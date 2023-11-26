CC=gcc
CFLAGS=-Wall --pedantic
CDEBUG=-DDEBUG
IMAGE='10.10.16.30.img'
OUTPUT_FILENAME='FORTASK'
SEARCH_FILENAME='FORTASK'

all:
	@echo "Usage: ./ntfs_extractor.exe [make|build|run|clean]"
build: clean
	@$(CC) $(CFLAGS) -o ntfs_extractor.exe ntfs.c
debug:
	@$(CC) $(CFLAGS) $(CDEBUG) -o ntfs_extractor.exe ntfs.c
run:
	@./ntfs_extractor.exe $(IMAGE) $(OUTPUT_FILENAME) $(SEARCH_FILENAME)
clean:
	@rm -vf *.exe *.txt