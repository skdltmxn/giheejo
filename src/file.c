#include <stdlib.h>
#include "types.h"
#include "file.h"

uint32 file_size(struct file_info *oi)
{
	long pos;
	if (!oi->fp)
		return 0;

	pos = ftell(oi->fp);
	fseek(oi->fp, 0, SEEK_END);
	oi->file_size = ftell(oi->fp);
	fseek(oi->fp, pos, SEEK_SET);

	return oi->file_size;
}