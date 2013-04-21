#ifndef __FILE_H
#define __FILE_H

#include <stdio.h>

struct file_info
{
	FILE *fp;
	uint32 file_size;
	void *file_format;
};

extern uint32 file_size(struct file_info *oi);

#endif