#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../types.h"
#include "../file.h"
#include "../config.h"
#include "../packer_info.h"
#include "../compressor.h"
#include "../buffer.h"
#include "pe_packer.h"
#include "pe.h"

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

	/* check number of sections */
	if (pf->img_hdr.nr_sections < 1
		|| pf->img_hdr.nr_sections > 96)
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

static int pe_image_opt_header(struct file_info *in, struct packer_info *pi)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;
	size_t read;

	read = fread(&pf->opt_hdr, sizeof(pf->opt_hdr), 1, in->fp);
	if (read != 1)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	/* only 32-bit executable is allowed */
	if (pf->opt_hdr.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	/* check valid Windows subsystems */
	if (pf->opt_hdr.subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI	
		&& pf->opt_hdr.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	printf("ImageBase: %08x\n", pf->opt_hdr.image_base);
	printf("Entry Point: %08x\n", pf->opt_hdr.image_base + pf->opt_hdr.entry);
	printf("File Align: %08x bytes\n", pf->opt_hdr.file_align);
	printf("Section Align: %08x bytes\n", pf->opt_hdr.section_align);

	return 1;
}

int pe_image_section_header(struct file_info *in, struct packer_info *pi)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;
	size_t read;
	int i;

	read = fread(pf->section_hdr, 
		sizeof(IMAGE_SECTION_HEADER), 
		pf->img_hdr.nr_sections, 
		in->fp);

	if (read != pf->img_hdr.nr_sections)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	for (i = 0; i < pf->img_hdr.nr_sections; ++i)
	{
		uint32 section_base = pf->opt_hdr.image_base + pf->section_hdr[i].virtual_addr;

		printf("Section #%d: %s\n", i + 1, pf->section_hdr[i].section_name);
		printf("from %08x to %08x\n", 
			section_base,
			section_base + pf->section_hdr[i].virtual_size - 1);
	}

	return 1;
}

int pe_pack(struct file_info *in, struct packer_info *pi, config_t *conf)
{
	FILE *fp = in->fp;
	uint32 filesize = file_size(in);
	uint32 pe_offset;
	struct pe_format *pf, *opf;
	struct buffer out_buf;
	byte *section_buffer = NULL;
	byte *comp_buf = NULL;
	int i, src_len = 0;
	uint32 dst_len;
	struct file_info out;
	int has_rsrc = 0;

	/* skip dos stub */
	pe_offset = pe_dos_stub(in, pi);
	if (!pe_offset)
		return 0;

	if (fseek(fp, pe_offset, SEEK_SET))
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	/* actual PE format begin */
	in->file_format = malloc(sizeof(struct pe_format));
	if (!in->file_format)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	pf = (struct pe_format *)in->file_format;

	/* read image header */
	if (!pe_image_header(in, pi))
		return 0;

	/* read optional header */
	if (!pe_image_opt_header(in, pi))
		return 0;

	if (!init_buffer(&out_buf, pf->opt_hdr.image_size))
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	pf->section_hdr = (IMAGE_SECTION_HEADER *)malloc(
		sizeof(IMAGE_SECTION_HEADER) * pf->img_hdr.nr_sections);
	if (!pf->section_hdr)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	/* read section headers */
	if (!pe_image_section_header(in, pi))
		return 0;

	section_buffer = (byte *)malloc(pf->opt_hdr.image_size);
	if (!section_buffer)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	for (i = 0; i < pf->img_hdr.nr_sections; ++i)
	{
		IMAGE_SECTION_HEADER *section = pf->section_hdr + i;
		
		/* skip resource section */
		if (!strcmp(section->section_name, ".rsrc"))
		{
			has_rsrc = 1;
			continue;
		}

		fseek(in->fp, section->raw_pointer, SEEK_SET);
		fread(section_buffer + section->virtual_addr - pf->opt_hdr.code_base,
			1,
			section->raw_size,
			in->fp);

		src_len += section->raw_size;
	}

	if (!add_buffer(&out_buf, section_buffer, src_len))
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}
	
	free(section_buffer);

	/* read IAT */
	if (!pe_iat(in, pi, &out_buf))
		return 0;

	comp_buf = (byte *)malloc(src_len);
	if (!comp_buf)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	if (compress(out_buf.p, src_len, comp_buf, &dst_len))
	{
		packer_set_error(pi, PACKER_COMPRESS_FAILED);
		return 0;
	}

	printf("[+] Size %d -> %u\n", src_len, dst_len);

	/*
		TODO: Modify headers
			  Construct IAT for packed executable
	*/


	out.fp = fopen(conf->output_filename, "wb");
	if (!out.fp)
	{
		packer_set_error(pi, PACKER_COMPRESS_FAILED);
		return 0;
	}

	opf = (struct pe_format *)malloc(sizeof(struct pe_format));
	if (!opf)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	memset(opf, 0, sizeof(struct pe_format));
	out.file_format = opf;

	memcpy(&opf->img_hdr, &pf->img_hdr, sizeof(IMAGE_FILE_HEADER));
	memcpy(&opf->opt_hdr, &pf->opt_hdr, sizeof(IMAGE_OPTIONAL_HEADER));

	/* reuse buffer */
	fseek(in->fp, 0, SEEK_SET);
	//fread(out_buf.p, 1, pe_offset, in->fp);
	//fwrite(comp_buf, 1, dst_len, out.fp);
	fwrite(out_buf.p, 1, out_buf.pos, out.fp);

	opf->img_hdr.nr_sections = has_rsrc ? 3 : 2;
	opf->opt_hdr.file_align = 0x200;

	fclose(out.fp);

	pe_destroy(&out);
	if (comp_buf)
		free(comp_buf);

	destroy_buffer(&out_buf);
	return 1;
}

void pe_destroy(struct file_info *fi)
{
	struct pe_format *pf = (struct pe_format *)fi->file_format;
	
	if (pf->section_hdr)
		free(pf->section_hdr);

	if (pf)
		free(pf);
}