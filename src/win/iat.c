#include <stdlib.h>
#include <string.h>
#include "../types.h"
#include "../file.h"
#include "../buffer.h"
#include "pe.h"
#include "../packer_info.h"
#include "win32_stub.h"

static const char *kernel32 = "KERNEL32.DLL";
static const char *k32_funcs[] = {
	"\x00\x00LoadLibraryA",
	"\x00\x00GetProcAddress",
	"\x00\x00""ExitProcess\x00"
};

static IMAGE_IMPORT_DESC *iid = NULL;
static uint32 dll_len_sum = 0;
static uint32 func_len_sum = 0;

int pe_iat(struct file_info *in, struct packer_info *pi, struct buffer *out_buf,
														 struct buffer *fake_iat)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;
	IMAGE_IMPORT_DESC *iid_iter;
	size_t read;
	uint32 iid_ptr;
	IMAGE_SECTION_HEADER *section = NULL;
	uint32 base = out_buf->pos;
	uint32 codebase = pf->opt_hdr.code_base;
	int i = 0;
	uint32 nr_iid = pf->opt_hdr.data_dir[DIR_IMPORT].size / sizeof(IMAGE_IMPORT_DESC) - 1;

	/* no import is not right */
	if (pf->opt_hdr.nr_data_dir < DIR_IMPORT
		|| !pf->opt_hdr.data_dir[DIR_IMPORT].rva)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	section = get_containing_section(pf, pf->opt_hdr.data_dir[DIR_IMPORT].rva);
	iid_ptr = RVA2RAW(pf->opt_hdr.data_dir[DIR_IMPORT].rva, 
		section->raw_pointer,
		section->virtual_addr);

	if (fseek(in->fp, iid_ptr, SEEK_SET))
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	iid = (IMAGE_IMPORT_DESC *)malloc(pf->opt_hdr.data_dir[DIR_IMPORT].size);
	if (!iid)
	{
		packer_set_error(pi, PACKER_NO_MEMORY);
		return 0;
	}

	/* read original IIDs */
	read = fread(iid, sizeof(IMAGE_IMPORT_DESC), 
			pf->opt_hdr.data_dir[DIR_IMPORT].size / sizeof(IMAGE_IMPORT_DESC), 
			in->fp);
	if (read != pf->opt_hdr.data_dir[DIR_IMPORT].size / sizeof(IMAGE_IMPORT_DESC))
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	iid_iter = iid;
	/* foreach IID */
	while (iid_iter->name)
	{
		uint32 offset = 0;
		int c = 1;
		byte *p = out_buf->p;
		uint32 dll_offset_pos = out_buf->pos; /* save pos for later */
		int i = 0;

		/* put garbage now - will be modified later */
		add_buffer(out_buf, "\xff\xff\xff\xff", 4);

		/* calculate offset to original IAT */
		offset = iid_iter->import_addr_table - pf->opt_hdr.code_base;
		add_buffer(out_buf, &offset, 4);

		/* add original function names */
		while (1)
		{
			offset = *(uint32 *)(p + iid_iter->import_name_table + i - codebase);
			if (!offset)
				break;

			c = 1;
			add_buffer(out_buf, &c, 1);

			/* skip ordinal */
			offset += 2;
			add_buffer(out_buf, p + offset - codebase,
				strlen((const char *)p + offset - codebase) + 1);

			i += 4;
		}

		c = 0;
		add_buffer(out_buf, &c, 1);

		/* working fake IAT from here */
		{
			char *dll_name = (char *)(p + iid_iter->name - codebase);
			uint32 dll_offset = pf->opt_hdr.data_dir[DIR_IMPORT].size + dll_len_sum;

			add_buffer_at(fake_iat, dll_name, strlen(dll_name) + 1, dll_offset);
			add_buffer_at(out_buf, &dll_offset, 4, dll_offset_pos);

			/* trick! */
			iid_iter->forward_chain = dll_offset + ((uint32)(iid_iter - iid) / sizeof(IMAGE_IMPORT_DESC));
			dll_len_sum += strlen(dll_name) + 1;
		}

		++iid_iter;
	} /* foreach IID */

	i = 0;
	add_buffer(out_buf, &i, 4);
	round_up_buffer(out_buf, 4);
	base = out_buf->pos;
	

	/* start over for pass 2 */
	iid_iter = iid;
	while (iid_iter->name)
	{
		byte *p = out_buf->p;
		char *dll_name = (char *)(p + iid_iter->name - codebase);
		uint32 iat_base = pf->opt_hdr.data_dir[DIR_IMPORT].size + dll_len_sum + i;
		uint32 func_base = pf->opt_hdr.data_dir[DIR_IMPORT].size 
			+ dll_len_sum + 4 * (nr_iid * 2 + 2) + func_len_sum;
		uint32 iat_value = 0;
		uint32 zero = 0;

		iid_iter->timestamp = 0;

		/* KERNEL32.dll */
		if (!stricmp(dll_name, kernel32))
		{
			uint32 temp = iat_base;
			iat_value = func_base;

			/* IAT */
			add_buffer_at(fake_iat, &iat_value, 4, iat_base);
			memcpy(&win32_stub[59], &temp, 4);
			temp += 4;
			iat_value += 14;

			add_buffer_at(fake_iat, &iat_value, 4, iat_base + 4);
			memcpy(&win32_stub[80], &temp, 4);
			temp += 4;
			iat_value += 16;

			add_buffer_at(fake_iat, &iat_value, 4, iat_base + 8);
			memcpy(&win32_stub[97], &temp, 4);

			add_buffer_at(fake_iat, &zero, 4, iat_base + 12);

			/* function names */
			add_buffer_at(fake_iat, k32_funcs[0], 14, func_base);
			add_buffer_at(fake_iat, k32_funcs[1], 16, func_base + 14);
			add_buffer_at(fake_iat, k32_funcs[2], 14, func_base + 14 + 16);

			func_len_sum += 44;
			i += 16;
		}
		/* other dlls */
		else
		{
			uint32 name_table = *(uint32 *)(p + iid_iter->import_name_table - codebase);
			char *func = (char *)(p + name_table + 2 - codebase);

			/* IAT */
			iat_value = func_base;
			add_buffer_at(fake_iat, &iat_value, 4, iat_base);
			add_buffer_at(fake_iat, &zero, 4, iat_base + 4);

			/* function name */
			add_buffer_at(fake_iat, func, strlen(func), func_base + 2);

			func_len_sum += strlen(func) + 2;
			i += 8;
		}

		iid_iter->import_addr_table = iat_base;
		add_buffer(fake_iat, iid_iter, sizeof(IMAGE_IMPORT_DESC));

		++iid_iter;
	}

	fake_iat->pos += dll_len_sum + sizeof(IMAGE_IMPORT_DESC);

	/*
	round_up_buffer(fake_iat, 4);
	add_buffer(out_buf, fake_iat->p, fake_iat->pos); 
	*/

	if (iid)
		free(iid);

	return base;
}

int pe_iat2(struct packer_info *pi, uint32 base, struct buffer *fake_iat)
{
	IMAGE_IMPORT_DESC *iid_iter;
	byte *p = fake_iat->p;
	iid_iter = (IMAGE_IMPORT_DESC *)fake_iat->p;

	while (iid_iter->name)
	{
		uint32 *iat = (uint32 *)(fake_iat->p + iid_iter->import_addr_table);

		iid_iter->name = iid_iter->forward_chain + base;
		iid_iter->forward_chain = 0;
		iid_iter->import_name_table = 0;
		iid_iter->import_addr_table += base;

		while (*iat)
		{
			*iat++ += base;
			fake_iat->pos += 4;
		}
		fake_iat->pos += 4;

		++iid_iter;
	}
	

	fake_iat->pos += func_len_sum;

	return 1;
}