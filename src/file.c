#include <stdlib.h>
#include "types.h"
#include "file.h"

uint32 file_size(struct file_info *fi)
{
	long pos;
	if (!fi->fp)
		return 0;

	pos = ftell(fi->fp);
	fseek(fi->fp, 0, SEEK_END);
	fi->file_size = ftell(fi->fp);
	fseek(fi->fp, pos, SEEK_SET);

	return fi->file_size;
}