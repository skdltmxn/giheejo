#ifndef __PE_H
#define __PE_H

typedef struct image_file_header
{
	uint16	machine;
	uint16	nr_sections;
	uint32	timestamp;
	uint32	symbol_table; /* must be zero */
	uint32	nr_symbols; /* must be zero */
	uint16	opt_hdr_size;
	uint16	characteristic;
} IMAGE_FILE_HEADER;

struct pe_format
{
	IMAGE_FILE_HEADER img_hdr;
};

#define DOS_STUB_SIZE	0x40

/* 
	There are more types actually,
	but out targets are x86 (maybe x64 too in the future...)
*/
#define	IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_I386		0x14c

#define IMAGE_FILE_EXECUTABLE_IMAGE	0x002
#define IMAGE_FILE_32BIT_MACHINE	0x100

#endif