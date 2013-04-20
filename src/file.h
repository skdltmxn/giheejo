#ifndef __FILE_H
#define __FILE_H

#include <stdio.h>

struct file_info
{
	FILE *fp;
	uint32 file_size;
	byte *buffer;
	uint32 buffer_size;
};

extern int file_open(const char *filename, const char *mode, struct file_info *f);
extern void file_close(struct file_info *f);
extern int file_seek(struct file_info *f, uint32 pos);
extern size_t file_read(struct file_info *f, uint32 length);
extern byte *file_buffer(struct file_info *f);
extern uint32 file_size(struct file_info *f);


#endif