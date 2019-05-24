Janus: Fuzzing File Systems via Two-Dimensional Input Space Exploration
===========================================

### Paper
* [Fuzzing File Systems via Two-Dimensional Input Space Exploration (IEEE S&P 2019)](https://gts3.org/assets/papers/2019/xu:janus.pdf)

### Overview
Janus is a general file system fuzzer. Janus finds memory corruptions in in-kernel file systems on Linux by exploring the input space of both images and syscalls simultaneously in an efficient and effective manner. Janus is implemented as an AFL variant. As an OS fuzzer, its target is not traditional VMs but Linux Kernel Library (https://github.com/lkl). Janus has found around 100 unique crashes in mainstream file systems with 32 CVEs assigned so far.

We currently release the image parsing support for ext4, btrfs and F2FS. Stay tuned for more extensions and the details of the found bugs! 

Here we explain the usage of Janus by fuzzing btrfs as an example.

### Tested Environment
- OS: Ubuntu 16.04 LTS
- clang 6.0.0
- gcc 5.0.0

### Preparation
- Compile ff-gcc (for instrumentation)
    - cd ff-gcc
    - make
- Compile the core fuzzing engine
    - cd core
    - make
- Compile (ported) lkl 4.17
    - cd lkl
    - For example, if you want to fuzz btrfs, ./compile -t btrfs -c
    - there are three target applications generated
        - ./tools/lkl/btrfs-fsfuzz          for fuzzing images only
        - ./tools/lkl/btrfs-executor        for fuzzing file operations only
        - ./tools/lkl/btrfs-combined        for fuzzing both (Janus)
- Compile image parser 
    - cd fs/btrfs
    - make
    - two output generated
        - btrfs_wrapper.so: AFL linked with this .so to compress and decompress an image
        - btrfs_standalone: this is used to release image offline given a compressed image and the original seed image. If you use *online* mode, you can release a batch of compressed images in an efficient way for reproducing.
    - Check fs/[fs name]/README.md for how to build in detail!

- Seed images
    - samples/evaluation        the seed images we used for evaluation in the paper 
    - samples/fuzzing           some additional images that we use for finding bugs
    - Let's assume we use samples/evaluation/btrfs-00.image here
        - Build the istat file for generating starting program 
            - cd istat
            - ./istat -i ../samples/evaluation/btrfs-00.image -t btrfs -o btrfs.istat
                - Usage: -i: seed image -t: file system type -o: output
            - Then we get the initial image status file: istat/btrfs-00.istat

- Run fuzzer
    - We need a directory to store seed programs based on the initial image status
        - mkdir prog
    - Create seed programs
        - ./core/create_corpus istat/btrfs.istat prog
            - Usage: create_corpus [istat file] [output dir]
        - To show readable C code of a serialized program
            - ./core/program_show prog/open_read0
    - Create the input directory and the output directory for Janus
        - mkdir input
        - mkdir output
        - ./core/afl-image-syscall/afl-fuzz -b btrfs -s fs/btrfs/btrfs_wrapper.so -e ./samples/evaluation/btrfs-00.image -S btrfs -y prog -i input -o output -m none -u 2 -- ./lkl/tools/lkl/btrfs-combined -t btrfs -p @@
            - -b: shared memory name for storing image (which should be distinct)
            - -s: fs (de)compressor
            - -e: seed image
            - -S: AFL argument (slave name) (which should be distinct)
                - No -M support
            - -y: the seed program directory
            - -i: AFL argument (input directory) (which should be distinct)
            - -o: AFL argument (output directory)
            - -u: #CPU
        - Janus supports fuzzing in parallel
            - Create a new tmux window
            - mkdir input2
            - ./core/afl-image-syscall/afl-fuzz -b btrfs2 -s fs/btrfs/btrfs_wrapper.so -e ./samples/evaluation/btrfs-00.image -S btrfs2 -y prog -i input2 -o output -m none -u 3 -- ./lkl/tools/lkl/btrfs-combined -t btrfs -p @@
                - Remember to use the same output folder for collaborative fuzzing
            - Off course, you can create more Janus instances like this.
        - How to check a generated testcase (compressed image + serialized program)
            - ./utils/afl-parse -i ./samples/evaluation/btrfs-00.image -t btrfs -f output/btrfs/crashes/id:000000,sig:11,src:000000,op:havoc,rep:32 -o tmp
                - Usage: -i: seed image -t: file system type -f: generated test case -o: output name
            - it will generate tmp.img: the mutated image to be mounted
            - tmp.c.raw: the serialized program 
            - tmp.c: the compilable program performed on the mutated image (for reproducing on a real OS)
            - You can use tmp.img and tmp.c.raw to reproduce the bug by btrfs-combined in LKL

    - If you only want to fuzz images (and run the fixed operations in LKL's fsfuzz.c):
        - ./core/afl-image/afl-fuzz -b btrfs -s fs/btrfs/btrfs_wrapper.so -e ./samples/evaluation/btrfs-00.image -S btrfs -i input -o output -m none -u 2 -- ./lkl/tools/lkl/btrfs-fsfuzz -t btrfs
    - If you only want to fuzz file operations (which are performed always on the same seed image):
        - ./core/afl-syscall/afl-fuzz -k -S btrfs -i prog -o output -m none -u 2 -- ./lkl/tools/lkl/btrfs-executor -t btrfs -i ./samples/evaluation/btrfs-00.image -p @@
        - Here the starting program folder is just the input directory

### Contacts
- Wen Xu (wen.xu@gatech.edu)
- Hyungon Moon (hyungon@unist.ac.kr)
- Sanidhya Kashyap (sanidhya@gatech.edu)
- Po-Ning Tseng (poning@gatech.edu)
- Taesoo Kim (taesoo@gatech.edu)
