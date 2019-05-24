#include <vector>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Image.hpp"
#include "Utils.hpp"

/*
Image stat format:
[ fileobjs_num ]
	[ len | relative path 
	| type
	| xattr_num 
		[ name_len | name ]
	]
*/

/************* FileObject **************/
void FileObject::show(const char *path) 
{
	if (path == NULL)
		printf("Path: %s\n", rel_path.c_str());
	else
		printf("Path: %s\n", path);
	printf("Type: ");
	switch (type) {
		case I_FILE:
			puts("file");
			break;
		case I_DIR:
			puts("dir");
			break;
		case I_SYMLINK:
			puts("symlink");
			break;
		case I_FIFO:
			puts("fifo");
			break;
		default:
			puts("ERROR");
	}
	puts("Xattrs: ");
	for (BufferObject* name : xattrs) {
		printf("name: ");
		print_binstr(name->buffer, name->size);
	// 	printf(" value: ");
	//	print_binstr((xattr.second)->buffer, (xattr.second)->size);
		printf("\n");
	}
}

/************* Image **************/
Image::~Image() {
	FileObject *fobj;
	for (std::vector<FileObject*>::iterator it = file_objs.begin();
		it != file_objs.end(); it++) {
		fobj = *it;
		delete fobj;
	}
}

void Image::show() {

	for (FileObject *fobj : file_objs) 
		fobj->show();	

	return;
}

Image* Image::deserialize(const char *path) {
	int fd = open(path, O_RDONLY);
	if (fd <= 0)
		return NULL;

	Image *image = new Image;

	uint32_t fileObjNum = 0;
	read(fd, &fileObjNum, sizeof(uint32_t));

	for (uint32_t i = 0; i < fileObjNum; i++) {

		FileObject *fobj = new FileObject;

		uint32_t len = 0;
		char *buf;

		read(fd, &len, sizeof(uint32_t));
		buf = (char *)malloc(len + 1);
		if (buf == NULL)
			goto exit;
		read(fd, buf, len);
		buf[len] = 0;

		fobj->rel_path = std::string(buf);
		free(buf);

		read(fd, &(fobj->type), sizeof(uint8_t));

		uint32_t xattr_num = 0;
		read(fd, &xattr_num, sizeof(uint32_t));

		for (uint32_t j = 0; j < xattr_num; j++) {

			uint8_t *name_buf;
			uint32_t name_len;

			read(fd, &name_len, sizeof(uint32_t));
			name_buf = (uint8_t *)malloc(name_len);
			if (name_buf == NULL)
				goto exit;
			read(fd, name_buf, name_len);

			fobj->xattrs.push_back(
				new BufferObject(name_buf, name_len)
			);
		}

		image->file_objs.push_back(fobj);
	}

	close(fd);
	return image;

exit:
	close(fd);
	return NULL;
}
