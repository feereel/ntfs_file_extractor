CC=gcc
CFLAGS=-Wall --pedantic
CDEBUG=-DDEBUG

all:
	@echo "Usage: ./ntfs_extractor.exe [make|build|run|clean]"
build: clean
	@$(CC) $(CFLAGS) -o ntfs_extractor.exe ntfs.c
debug:
	@$(CC) $(CFLAGS) $(CDEBUG) -o ntfs_extractor.exe ntfs.c
run:
	@./ntfs_extractor.exe ntfs_1ff7db4ed8350c6180f54a9ffbf224c7.img
clean:
	@rm -vf *.exe *.txt