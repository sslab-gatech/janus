ALL = image_test create_corpus program_show program_test afl
CXX ?= g++
CXXFLAGS = -std=c++11 -g

all: $(ALL)

image_test: image_test.o Image.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

create_corpus: create_corpus.o Image.o Program.o Utils.o Constants.o SyscallMutator.o
	$(CXX) $(CXXFLAGS) -o $@ $^

program_show: program_show.o Image.o Program.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

program_test: program_test.o Image.o Program.o Utils.o Constants.o
	$(CXX) $(CXXFLAGS) -o $@ $^

afl:
	make -C afl-image
	make -C afl-image/llvm_mode
	make -C afl-syscall 
	make -C afl-image-syscall 

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.o
	rm -rf $(ALL)
	make -C afl-image clean
	make -C afl-image/llvm_mode clean
	make -C afl-syscall clean
	make -C afl-image-syscall clean
