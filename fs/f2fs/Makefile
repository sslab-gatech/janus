CXXFLAGS=-std=c++11
CFLAGS=-std=c99
CC=gcc

all: standalone wrapper

standalone: 
	$(CXX) $(CXXFLAGS) -I../ -c f2fs_fuzzer.cc -g
	$(CXX) $(CXXFLAGS) -I../ -c f2fs_standalone.cc -g
	$(CXX) $(CXXFLAGS) -o f2fs_standalone f2fs_standalone.o f2fs_fuzzer.o

wrapper:
	$(CXX) $(CXXFLAGS) -fPIC -I../ -c f2fs_fuzzer.cc -g
	$(CXX) $(CXXFLAGS) -fPIC -I../ -c f2fs_wrapper.cc -g 
	$(CXX) -fpic -shared -o f2fs_wrapper.so f2fs_wrapper.o f2fs_fuzzer.o

clean:
	rm -f *.o *.so *.a
	rm -f f2fs_standalone f2fs_general_standalone
	rm -f meta.img out.img log
