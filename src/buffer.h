#ifndef __BUFFER_H
#define __BUFFER_H

struct buffer
{
	byte *p;
	uint32 pos;
	uint32 max_size;
};

extern int init_buffer(struct buffer *buf, uint32 size);
extern int add_buffer(struct buffer *buf, const void *data, uint32 size);
extern int add_buffer_at(struct buffer *buf, const void *data, uint32 size, uint32 pos);
extern int round_up_buffer(struct buffer *buf, uint32 x);
extern void destroy_buffer(struct buffer *buf);

#endif