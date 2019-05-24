#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ext4_fuzzer.hh"
#include "utils.hh"

/* usage: 
   ./ext4_standalone test in_image out_image meta_image
    - generate meta_image from in_image, and recover it back to out_image
   ./ext4_standalone repro in_image out_image meta_image
 */

int main(int argc, char *argv[]) 
{

  if (argc < 4) {
    fprintf(stderr, "invalid arg\n");
    return 1;
  }

  if (!strcmp(argv[1], "test")) {
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    const char *meta_path = argv[4];

    struct stat st;
    lstat(in_path, &st);

    void *image_buffer = malloc(st.st_size);
    ext4_fuzzer.compress(in_path, image_buffer, meta_path);

    lstat(meta_path, &st);
    
    void *tmp_buffer = malloc(st.st_size);
    int fd = open(meta_path, O_RDONLY);
    if (read(fd, tmp_buffer, st.st_size) != st.st_size)
      FATAL("reading %s failed.", argv[2]);
    close(fd);

    ext4_fuzzer.decompress(tmp_buffer, st.st_size, true);

    ext4_fuzzer.sync_to_file(out_path);

    free(tmp_buffer);
    free(image_buffer);

  } else if (!strcmp(argv[1], "repro")) {
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    const char *meta_path = argv[4];

    struct stat st;
    lstat(in_path, &st);

    void *image_buffer = malloc(st.st_size);
    ext4_fuzzer.compress(in_path, image_buffer);
    
    lstat(meta_path, &st);

    void *tmp_buffer = malloc(st.st_size);
    int fd = open(meta_path, O_RDONLY);
    if (read(fd, tmp_buffer, st.st_size) != st.st_size)
      FATAL("reading %s failed.", argv[2]);
    close(fd);

    ext4_fuzzer.decompress(tmp_buffer, st.st_size);

    ext4_fuzzer.sync_to_file(out_path);

    free(tmp_buffer);
    free(image_buffer);
  } else if (!strcmp(argv[1], "online")) {

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *in_path = argv[2];
    const char *out_path = argv[3];
    
    struct stat st;
    lstat(in_path, &st);

    void *image_buffer;
    int fd = open(out_path, O_RDWR | O_TRUNC, 0666);
    size_t image_size = st.st_size;
    ftruncate(fd, image_size);
    image_buffer = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (image_buffer == MAP_FAILED) {
        FATAL("Mapping image buffer failed.");
        close(fd);
        exit(1);
    }
    close(fd);
    ext4_fuzzer.compress(in_path, image_buffer);

    printf("READY\n");
    char meta_path[256];
    memset(meta_path, 0, sizeof(meta_path));

    while (1) {
        fgets(meta_path, 255, stdin);
        if (!strcmp(meta_path, "EOF")) break;
        lstat(meta_path, &st);
        void *tmp_buffer = malloc(st.st_size);
        int fd = open(meta_path, O_RDONLY);
        if (read(fd, tmp_buffer, st.st_size) != st.st_size) {
            FATAL("reading %s failed.", meta_path);
        }
        close(fd);
        ext4_fuzzer.decompress(tmp_buffer, st.st_size, true);
        msync(image_buffer, image_size, MS_SYNC);
        free(tmp_buffer);
        printf("OK\n");
    } 

    munmap(image_buffer, image_size);
    close(fd);

  } else {
    fprintf(stderr, "arg not supported!\n");
    return 1;
  }

  return 0;
}
