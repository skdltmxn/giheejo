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
#include "win32_stub.h"

byte win32_stub[] = {
	0x60,
	0x68, 0xde, 0xad, 0xbe, 0xef,
	0x68, 0xde, 0xad, 0xbe, 0xef,
	0x68, 0xde, 0xad, 0xbe, 0xef,
	0xe8, 0x57, 0x00, 0x00, 0x00,
	0x83, 0xc4, 0x0c,
	0xbe, 0xde, 0xad, 0xbe, 0xef,
	0x8d, 0xbe, 0xde, 0xad, 0xbe, 0xef,
	0x8b, 0x07,
	0x09, 0xc0, 0x74, 0x3c, 0x8b, 0x5f, 0x04, 0x8d,
	0x84, 0x30, 0xde, 0xad, 0xbe, 0xef, 0x01, 0xf3,
	0x50, 0x83, 0xc7, 0x08, 0xff, 0x96, 0xde, 0xad,
	0xbe, 0xef, 0x95, 0x8a, 0x07, 0x47, 0x08, 0xc0,
	0x74, 0xdc, 0x89, 0xf9, 0x57, 0x48, 0xf2, 0xae,
	0x55, 0xff, 0x96, 0xde, 0xad, 0xbe, 0xef, 0x09,
	0xc0, 0x74, 0x07, 0x89, 0x03, 0x83, 0xc3, 0x04,
	0xeb, 0xe1, 0xff, 0x96, 0xde, 0xad, 0xbe, 0xef,
	0xb8, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xe0,
	0x55, 0x57, 0x56, 0x53, 0x51, 0x52, 0x83, 0xec, 0x0c,
	0xfc, 0x8b, 0x74, 0x24, 0x28, 0x8b, 0x7c, 0x24,
	0x30, 0xbd, 0x03, 0x00, 0x00, 0x00, 0x31, 0xc0,
	0x31, 0xdb, 0xac, 0x3c, 0x11, 0x76, 0x1b, 0x2c,
	0x0e, 0xeb, 0x22, 0x05, 0xff, 0x00, 0x00, 0x00,
	0x8a, 0x1e, 0x46, 0x08, 0xdb, 0x74, 0xf4, 0x8d,
	0x44, 0x18, 0x15, 0xeb, 0x10, 0x89, 0xf6, 0x8a,
	0x06, 0x46, 0x3c, 0x10, 0x73, 0x41, 0x08, 0xc0,
	0x74, 0xe6, 0x83, 0xc0, 0x06, 0x89, 0xc1, 0x31,
	0xe8, 0xc1, 0xe9, 0x02, 0x21, 0xe8, 0x8b, 0x16,
	0x83, 0xc6, 0x04, 0x89, 0x17, 0x83, 0xc7, 0x04,
	0x49, 0x75, 0xf3, 0x29, 0xc6, 0x29, 0xc7, 0x8a,
	0x06, 0x46, 0x3c, 0x10, 0x73, 0x19, 0xc1, 0xe8,
	0x02, 0x8a, 0x1e, 0x8d, 0x97, 0xff, 0xf7, 0xff,
	0xff, 0x8d, 0x04, 0x98, 0x46, 0x29, 0xc2, 0x8b,
	0x0a, 0x89, 0x0f, 0x01, 0xef, 0xeb, 0x6e, 0x3c,
	0x40, 0x72, 0x34, 0x89, 0xc1, 0xc1, 0xe8, 0x02,
	0x8d, 0x57, 0xff, 0x83, 0xe0, 0x07, 0x8a, 0x1e,
	0xc1, 0xe9, 0x05, 0x8d, 0x04, 0xd8, 0x46, 0x29,
	0xc2, 0x83, 0xc1, 0x04, 0x39, 0xe8, 0x73, 0x35,
	0xeb, 0x6d, 0x05, 0xff, 0x00, 0x00, 0x00, 0x8a,
	0x1e, 0x46, 0x08, 0xdb, 0x74, 0xf4, 0x8d, 0x4c,
	0x18, 0x24, 0x31, 0xc0, 0xeb, 0x0d, 0x90, 0x3c,
	0x20, 0x72, 0x74, 0x83, 0xe0, 0x1f, 0x74, 0xe7,
	0x8d, 0x48, 0x05, 0x66, 0x8b, 0x06, 0x8d, 0x57,
	0xff, 0xc1, 0xe8, 0x02, 0x83, 0xc6, 0x02, 0x29,
	0xc2, 0x39, 0xe8, 0x72, 0x3a, 0x8d, 0x44, 0x0f,
	0xfd, 0xc1, 0xe9, 0x02, 0x8b, 0x1a, 0x83, 0xc2,
	0x04, 0x89, 0x1f, 0x83, 0xc7, 0x04, 0x49, 0x75,
	0xf3, 0x89, 0xc7, 0x31, 0xdb, 0x8a, 0x46, 0xfe,
	0x21, 0xe8, 0x0f, 0x84, 0x3f, 0xff, 0xff, 0xff,
	0x8b, 0x16, 0x01, 0xc6, 0x89, 0x17, 0x01, 0xc7,
	0x8a, 0x06, 0x46, 0xe9, 0x77, 0xff, 0xff, 0xff,
	0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00, 0x87,
	0xd6, 0x29, 0xe9, 0xf3, 0xa4, 0x89, 0xd6, 0xeb,
	0xd4, 0x81, 0xc1, 0xff, 0x00, 0x00, 0x00, 0x8a,
	0x1e, 0x46, 0x08, 0xdb, 0x74, 0xf3, 0x8d, 0x4c,
	0x0b, 0x0c, 0xeb, 0x17, 0x8d, 0x76, 0x00, 0x3c,
	0x10, 0x72, 0x2c, 0x89, 0xc1, 0x83, 0xe0, 0x08,
	0xc1, 0xe0, 0x0d, 0x83, 0xe1, 0x07, 0x74, 0xdf,
	0x83, 0xc1, 0x05, 0x66, 0x8b, 0x06, 0x83, 0xc6,
	0x02, 0x8d, 0x97, 0x00, 0xc0, 0xff, 0xff, 0xc1,
	0xe8, 0x02, 0x74, 0x2b, 0x29, 0xc2, 0xe9, 0x7a,
	0xff, 0xff, 0xff, 0x8d, 0x74, 0x26, 0x00, 0xc1,
	0xe8, 0x02, 0x8a, 0x1e, 0x8d, 0x57, 0xff, 0x8d,
	0x04, 0x98, 0x46, 0x29, 0xc2, 0x8a, 0x02, 0x88,
	0x07, 0x8a, 0x5a, 0x01, 0x88, 0x5f, 0x01, 0x83,
	0xc7, 0x02, 0xe9, 0x6e, 0xff, 0xff, 0xff, 0x83,
	0xf9, 0x06, 0x0f, 0x95, 0xc0, 0x8b, 0x54, 0x24,
	0x28, 0x03, 0x54, 0x24, 0x2c, 0x39, 0xd6, 0x77,
	0x1c, 0x72, 0x13, 0xf7, 0xd8, 0x83, 0xc4, 0x0c,
	0x5a, 0x59, 0x5b, 0x5e, 0x5f, 0x5d, 0xc3, 0xb8,
	0x01, 0x00, 0x00, 0x00, 0xeb, 0xed, 0xb8, 0x08,
	0x00, 0x00, 0x00, 0xeb, 0xe6, 0xb8, 0x04, 0x00,
	0x00, 0x00, 0xeb, 0xdf, 0x90
};

#define ALIGN(x, n)	((x) + ((n) - ((x) % (n) ? ((x) % (n)) : (n))))

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

	return 1;
}

int pe_pack(struct file_info *in, struct packer_info *pi, config_t *conf)
{
	FILE *fp = in->fp;
	uint32 filesize = file_size(in);
	uint32 pe_offset;
	struct pe_format *pf, *opf;
	struct buffer out_buf;
	struct buffer fake_iat;
	byte *section_buffer = NULL;
	byte *comp_buf = NULL;
	int i, src_len = 0;
	uint32 dst_len, section_len = 0;
	struct file_info out;
	int has_rsrc = 0;
	IMAGE_SECTION_HEADER *rsrc_section = NULL;

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

		src_len += ALIGN(section->virtual_size, pf->opt_hdr.section_align);
	}

	if (!add_buffer(&out_buf, section_buffer, src_len))
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}
	
	free(section_buffer);
	section_len = out_buf.pos;

	/* read IAT */
	init_buffer(&fake_iat, 1024);
	src_len = pe_iat(in, pi, &out_buf, &fake_iat);
	if (!src_len)
		return 0;

	comp_buf = (byte *)malloc(src_len);
	if (!comp_buf)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	/* compress sections + original IAT */
	if (compress(out_buf.p, src_len, comp_buf, &dst_len))
	{
		packer_set_error(pi, PACKER_COMPRESS_FAILED);
		return 0;
	}

	printf("[+] Size of code before compression: %d\n", src_len);
	printf("[+] Size of code after compression: %u\n", dst_len);

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

	memcpy(&opf->img_hdr, &pf->img_hdr, sizeof(pf->img_hdr));
	memcpy(&opf->opt_hdr, &pf->opt_hdr, sizeof(pf->opt_hdr));

	/* construct new section headers */
	opf->img_hdr.nr_sections = has_rsrc ? 3 : 2;
	opf->section_hdr = (IMAGE_SECTION_HEADER *)malloc(
		sizeof(IMAGE_SECTION_HEADER) * opf->img_hdr.nr_sections);
	memset(opf->section_hdr, 0, sizeof(IMAGE_SECTION_HEADER) * opf->img_hdr.nr_sections);

	if (!opf->section_hdr)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}
	strcpy(opf->section_hdr[0].section_name, "HEE");
	strcpy(opf->section_hdr[1].section_name, "JO");
	if (has_rsrc)
		strcpy(opf->section_hdr[2].section_name, ".rsrc");

	rsrc_section = find_section(pf, ".rsrc");

	opf->section_hdr[0].raw_size = 0;
	opf->section_hdr[1].raw_size = ALIGN(fake_iat.pos + dst_len + sizeof(win32_stub), 0x200);
	
	opf->section_hdr[1].virtual_size = ALIGN(opf->section_hdr[1].raw_size, 0x1000);

	opf->section_hdr[0].raw_pointer = 0x400;
	opf->section_hdr[1].raw_pointer = 0x400;
	

	opf->section_hdr[0].virtual_addr = pf->opt_hdr.code_base;
	opf->section_hdr[1].virtual_addr = ALIGN(out_buf.pos, 0x1000);
	
	opf->section_hdr[0].virtual_size = opf->section_hdr[1].virtual_addr - opf->section_hdr[0].virtual_addr;

	opf->section_hdr[0].characteristics = (SECTION_UNINIT_DATA | SECTION_WRITE | SECTION_READ | SECTION_EXEC);
	opf->section_hdr[1].characteristics = (SECTION_INIT_DATA | SECTION_WRITE | SECTION_READ | SECTION_EXEC);
	
	if (rsrc_section)
	{
		opf->section_hdr[2].virtual_size = ALIGN(opf->section_hdr[2].raw_size, 0x1000);
		opf->section_hdr[2].raw_pointer = opf->section_hdr[1].raw_pointer + opf->section_hdr[1].raw_size;
		opf->section_hdr[2].virtual_addr = opf->section_hdr[1].virtual_addr + opf->section_hdr[1].virtual_size;

		opf->section_hdr[2].raw_size = rsrc_section->raw_size;
		opf->section_hdr[2].characteristics = (SECTION_UNINIT_DATA | SECTION_WRITE | SECTION_READ);

		opf->opt_hdr.image_size = opf->section_hdr[2].virtual_addr + opf->section_hdr[2].virtual_size;
		opf->opt_hdr.data_size = opf->section_hdr[2].virtual_size;
		opf->opt_hdr.data_base = opf->section_hdr[2].virtual_addr;

		opf->opt_hdr.data_dir[DIR_RESOURCE].rva = opf->section_hdr[2].virtual_addr;
		opf->opt_hdr.data_dir[DIR_RESOURCE].size = opf->section_hdr[2].raw_size;
	}
	else
	{
		opf->opt_hdr.image_size = opf->section_hdr[1].virtual_addr + opf->section_hdr[1].virtual_size;
		opf->opt_hdr.data_size = opf->section_hdr[1].virtual_size;
		opf->opt_hdr.data_base = opf->section_hdr[1].virtual_addr;
	}

	
	opf->opt_hdr.bss_size = opf->section_hdr[0].virtual_size;
	opf->opt_hdr.code_size = opf->section_hdr[1].virtual_size;
	opf->opt_hdr.code_base = opf->section_hdr[1].virtual_addr;
	opf->opt_hdr.file_align = 0x200;
	opf->opt_hdr.data_dir[DIR_IMPORT].rva = opf->section_hdr[1].virtual_addr + dst_len;
	opf->opt_hdr.data_dir[DIR_IAT].rva = 0;
	opf->opt_hdr.data_dir[DIR_IAT].size = 0;
	
	opf->opt_hdr.data_dir[DIR_LOADCONFIG].rva = 0;
	opf->opt_hdr.data_dir[DIR_LOADCONFIG].size = 0;

	pe_iat2(pi, opf->section_hdr[1].virtual_addr + dst_len, &fake_iat);
	opf->opt_hdr.entry = opf->section_hdr[1].virtual_addr + dst_len + fake_iat.pos;

	/* reuse buffer */
	fseek(in->fp, 0, SEEK_SET);
	fread(out_buf.p, 1, pe_offset, in->fp);

	fwrite(out_buf.p, 1, pe_offset, out.fp);
	fwrite("\x50\x45\x00\x00", 1, 4, out.fp);

	/* headers */
	fwrite(&opf->img_hdr, 1, sizeof(IMAGE_FILE_HEADER), out.fp);
	fwrite(&opf->opt_hdr, 1, sizeof(IMAGE_OPTIONAL_HEADER), out.fp);
	fwrite(opf->section_hdr, sizeof(IMAGE_SECTION_HEADER), opf->img_hdr.nr_sections, out.fp);

	/* compressed data */
	fseek(out.fp, 0x400, SEEK_SET);
	fwrite(comp_buf, 1, dst_len, out.fp);
	fwrite(fake_iat.p, 1, fake_iat.pos, out.fp);

	/* generate unpacker */
	{
		uint32 value = pf->opt_hdr.image_base + pf->opt_hdr.code_base;

		memcpy(&win32_stub[2], &value, 4); /* dst */
		memcpy(&win32_stub[25], &value, 4);

		value = dst_len;
		memcpy(&win32_stub[7], &value, 4); /* src_len */

		value = pf->opt_hdr.image_base + opf->section_hdr[1].virtual_addr;
		memcpy(&win32_stub[12], &value, 4); /* src */

		value = section_len;
		memcpy(&win32_stub[31], &value, 4);

		value = opf->opt_hdr.data_dir[DIR_IMPORT].rva - pf->opt_hdr.code_base;
		memcpy(&win32_stub[47], &value, 4);

		memcpy(&value, &win32_stub[59], 4);
		value += opf->section_hdr[1].virtual_addr + dst_len - pf->opt_hdr.code_base;
		memcpy(&win32_stub[59], &value, 4);

		memcpy(&value, &win32_stub[80], 4);
		value += opf->section_hdr[1].virtual_addr + dst_len - pf->opt_hdr.code_base;
		memcpy(&win32_stub[80], &value, 4);

		memcpy(&value, &win32_stub[97], 4);
		value += opf->section_hdr[1].virtual_addr + dst_len - pf->opt_hdr.code_base;
		memcpy(&win32_stub[97], &value, 4);

		value = pf->opt_hdr.entry + pf->opt_hdr.image_base;
		memcpy(&win32_stub[102], &value, 4);
	}

	fwrite(win32_stub, 1, sizeof(win32_stub), out.fp);

	if (rsrc_section)
	{
		byte *rsrc_c = (byte *)malloc(rsrc_section->raw_size);
		fseek(out.fp, opf->section_hdr[2].raw_pointer, SEEK_SET);
		fseek(in->fp, rsrc_section->raw_pointer, SEEK_SET);
		fread(rsrc_c, 1, rsrc_section->raw_size, in->fp);
		fwrite(rsrc_c, 1, rsrc_section->raw_size, out.fp);
	}
	else
	{
		long cur = ftell(out.fp);
		cur = ALIGN(cur, 0x200) - 1;
		fseek(out.fp, cur, SEEK_SET);
		fputc(0, out.fp);
	}

	/* cleanups */
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