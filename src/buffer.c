#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "buffer.h"

int init_buffer(struct buffer *buf, uint32 size)
{
	if (!buf || size < 1)
		return -1;

	buf->p = (byte *)malloc(size);
	if (!buf->p)
		return 0;
	
	memset(buf->p, 0, size);
	buf->pos = 0;
	buf->max_size = size;

	return 1;
}

int add_buffer(struct buffer *buf, const void *data, uint32 size)
{
	if (!buf)
		return 0;

	if (size > (buf->max_size - buf->pos))
	{
		buf->p = (byte *)realloc(buf->p, buf->max_size * 2);
		if (!buf->p)
			return 0;
	}

	memcpy(buf->p + buf->pos, data, size);
	buf->pos += size;

	return 1;
}

int add_buffer_at(struct buffer *buf, const void *data, uint32 size, uint32 pos)
{
	if (!buf)
		return 0;

	if (pos > buf->max_size)
		return 0;

	memcpy(buf->p + pos, data, size);
	return 1;
}

int round_up_buffer(struct buffer *buf, uint32 x)
{
	int remain = x - (buf->pos % x);

	if (buf->pos + remain > buf->max_size)
		return 0;

	buf->pos += remain;
	return 1;
}

void destroy_buffer(struct buffer *buf)
{
	if (buf && buf->p)
		free(buf->p);
}