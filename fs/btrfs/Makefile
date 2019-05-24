CXXFLAGS=-std=c++11 -I../
CFLAGS=-std=c99 -I../
CC=gcc

all: standalone wrapper 

standalone:
	$(CC) $(CFLAGS) -c crc32c.c
	$(CXX) $(CXXFLAGS) -c btrfs_fuzzer.cc
	$(CXX) $(CXXFLAGS) -c btrfs_standalone.cc
	$(CXX) $(CXXFLAGS) -o btrfs_standalone btrfs_standalone.o btrfs_fuzzer.o crc32c.o

wrapper:
	$(CC) -fPIC $(CFLAGS) -c crc32c.c
	$(CXX) -fPIC $(CXXFLAGS) -c btrfs_fuzzer.cc
	$(CXX) -fPIC $(CXXFLAGS) -c btrfs_wrapper.cc
	$(CXX) -fPIC -shared $(CXXFLAGS) -o btrfs_wrapper.so btrfs_wrapper.o btrfs_fuzzer.o crc32c.o

clean:
	rm -f *.o
	rm -f *_standalone
	rm -f btrfs_wrapper.so
	rm -f meta.img out.img 
