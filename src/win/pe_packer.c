#include <stdlib.h>
#include <stdio.h>
#include "../types.h"
#include "../file.h"
#include "../packer_info.h"
#include "../packer_error.h"
#include "pe_packer.h"
#include "pe.h"

static int pe_image_header(struct file_info *in, struct packer_info *pi)
{
	byte signature[4];
	struct pe_format *pf = (struct pe_format *)in->file_format;
	size_t read;

	read = fread(signature, 1, 4, in->fp);
	if (read != 4)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	if (*(uint32 *)signature != 0x00004550)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	read = fread(&pf->img_hdr, sizeof(pf->img_hdr), 1, in->fp);
	if (read != 1)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	printf("Machine: %x\n# of sections: %u\nTimestamp: %x\n", 
		pf->img_hdr.machine,
		pf->img_hdr.nr_sections,
		pf->img_hdr.timestamp);

	return 1;
}

static uint32 pe_dos_stub(struct file_info *in, struct packer_info *pi)
{
	byte dos_stub[DOS_STUB_SIZE];

	if (in->file_size < DOS_STUB_SIZE)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	fread(dos_stub, 1, DOS_STUB_SIZE, in->fp);

	if (dos_stub[0] != 'M' || dos_stub[1] != 'Z')
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	return *(uint32 *)&dos_stub[0x3c];
}

int pe_pack(struct file_info *in, struct packer_info *pi)
{
	FILE *fp = in->fp;
	uint32 filesize = file_size(in);
	uint32 pe_offset;

	pe_offset = pe_dos_stub(in, pi);
	if (!pe_offset)
		return 0;

	if (fseek(fp, pe_offset, SEEK_SET))
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	in->file_format = malloc(sizeof(struct pe_format));
	if (!in->file_format)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	if (!pe_image_header(in, pi))
		return 0;

	return 1;
}