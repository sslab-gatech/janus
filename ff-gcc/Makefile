ALL = ff-gcc
CXXFLAGS = -std=c++11

all: $(ALL)

ff-gcc: ff-gcc.o
	$(CXX) $(CXXFLAGS) -o $@ $<

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(ALL) *.o
