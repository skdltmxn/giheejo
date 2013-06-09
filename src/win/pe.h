#ifndef __PE_H
#define __PE_H

typedef struct image_file_header
{
	uint16	machine;
	uint16	nr_sections;
	uint32	timestamp;
	uint32	symbol_table;	/* must be zero */
	uint32	nr_symbols;		/* must be zero */
	uint16	opt_hdr_size;
	uint16	characteristic;
} IMAGE_FILE_HEADER;

struct version_info
{
	uint16 major;
	uint16 minor;
};

typedef struct image_data_directory
{
	uint32	rva;
	uint32	size;
} IMAGE_DATA_DIRECTORY;

/*
 * This structure is for PE32 (not PE32+)
 */
typedef struct image_optional_header
{
	/* Standard Fields */
	uint16	magic;
	byte	linker_ver_maj;
	byte	linker_ver_min;
	uint32	code_size;
	uint32	data_size;
	uint32	bss_size;
	uint32	entry;
	uint32	code_base;
	uint32	data_base;

	/* Windows Specific Fields */
	uint32	image_base;
	uint32	section_align;
	uint32	file_align;
	struct version_info os_version;
	struct version_info img_version;
	struct version_info sub_version;
	uint32	reserved;	/* must be zero */
	uint32	image_size;
	uint32	image_header;
	uint32	checksum;
	uint16	subsystem;
	uint16	dll_characteristics;
	uint32	reserved_stack_size;
	uint32	commit_stack_size;
	uint32	reserved_heap_size;
	uint32	commit_heap_size;
	uint32	loader_flags;
	uint32	nr_data_dir;
	IMAGE_DATA_DIRECTORY data_dir[16];
} IMAGE_OPTIONAL_HEADER;

typedef struct image_section_header
{
	char	section_name[8];
	uint32	virtual_size;
	uint32	virtual_addr;
	uint32	raw_size;
	uint32	raw_pointer;
	uint32	unused[3];	/* zero */
	uint32	characteristics;
} IMAGE_SECTION_HEADER;

typedef struct image_import_desc
{
	uint32	import_name_table;	/* INT in RVA */
	uint32	timestamp;
	uint32	forward_chain;
	uint32	name;
	uint32	import_addr_table;	/* IAT in RVA */
} IMAGE_IMPORT_DESC;

typedef struct image_import_name
{
	uint16	hint;		/* ordinal */
	byte	name[1];	/* function name */
} IMAGE_IMPORT_NAME;

/* Main PE format */
struct pe_format
{
	IMAGE_FILE_HEADER		img_hdr;
	IMAGE_OPTIONAL_HEADER	opt_hdr;
	IMAGE_SECTION_HEADER	*section_hdr;
};

#define DOS_STUB_SIZE	0x40

/* 
	There are more types actually,
	but our targets are x86 (maybe x64 too in the future...)
*/
#define	IMAGE_FILE_MACHINE_AMD64	0x8664
#define IMAGE_FILE_MACHINE_I386		0x14c

#define IMAGE_FILE_EXECUTABLE_IMAGE	0x002
#define IMAGE_FILE_32BIT_MACHINE	0x100

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC	0x10b

/* Windows subsystems */
#define IMAGE_SUBSYSTEM_WINDOWS_GUI		2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI		3

enum
{
		DIR_EXPORT,
		DIR_IMPORT,
		DIR_RESOURCE,
		DIR_EXCEPTION,
		DIR_SECURITY,
		DIR_BASERELOC,
		DIR_DEBUG,
		DIR_COPYRIGHT,
		DIR_GLOBALPTR,
		DIR_TLS,
		DIR_LOADCONFIG,
		DIR_BOUNDIMPORT,
		DIR_IAT,
		DIR_DELAYIMPORT,
		DIR_COMDESC,
		DIR_RESERVED
};

#define RVA2RAW(rva, file_base, section_base) \
	((file_base) + (rva) - (section_base))

extern IMAGE_SECTION_HEADER *get_containing_section(struct pe_format *pf,
													uint32 rva);

#endif