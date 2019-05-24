#include "Image.hpp"

int main(int argc, char *argv[]) {

	if (argc != 2)
		return 1;

	char *stat_file = argv[1];

	Image *image = Image::deserialize(stat_file);
	image->show();
	delete image;

	return 0;
}
