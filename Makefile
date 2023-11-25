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
	@./ntfs_extractor.exe 10.10.16.30.img
clean:
	@rm -vf *.exe *.txt