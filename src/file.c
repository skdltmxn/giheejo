#include <stdlib.h>
#include "types.h"
#include "file.h"

/*
 * @brief	Opens given file in given mode
 * @param	filename - name of file to open
			mode - same mode used in fopen
 * @return	1 on success, 0 on failure
 */
int file_open(const char *filename, const char *mode, struct file_info *f)
{
	FILE *fp = fopen(filename, mode);
	if (!fp)
		return 0;

	f->fp = fp;
	f->buffer = NULL;
	f->buffer_size = 0;
	
	fseek(fp, 0, SEEK_END);
	f->file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return 1;
}

/*
 * @brief	Closes file
 * @param	f - file to close
 */
void file_close(struct file_info *f)
{
	fclose(f->fp);
	if (f->buffer)
		free(f->buffer);
}

int file_seek(struct file_info *f, uint32 pos)
{
	if (!f->fp)
		return 0;

	return fseek(f->fp, pos, SEEK_SET);
}

size_t file_read(struct file_info *f, uint32 length)
{
	size_t ret;

	if (!f->fp)
		return 0;

	if (f->buffer_size < length)
		f->buffer = (byte *)realloc(f->buffer, length);

	ret = fread(f->buffer, 1, length, f->fp);

	if (ret != length)
	{
		if (ferror(f->fp))
			return 0;
	}

	return ret;
}

inline byte *file_buffer(struct file_info *f)
{
	return f->buffer;
}

inline uint32 file_size(struct file_info *f)
{
	return f->file_size;
}