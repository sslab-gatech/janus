### Build (f2fs support)
Note that we rely on dump.f2fs in f2fsprogs in the (de)compressor.
$ make
$ cd f2fsprogs
$ ./configure
$ make -j
$ sudo make install
