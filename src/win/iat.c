#include <stdlib.h>
#include <string.h>
#include "../types.h"
#include "../file.h"
#include "../buffer.h"
#include "pe.h"
#include "../packer_info.h"

static const char *kernel32 = "KERNEL32.DLL";
static const char *k32_funcs[] = {
	"\x00\x00LoadLibraryA",
	"\x00\x00GetProcAddress",
	"\x00\x00""ExitProcess\x00"
};

int pe_iat(struct file_info *in, struct packer_info *pi, struct buffer *out_buf)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;
	IMAGE_IMPORT_DESC *iid, *iid_iter;
	size_t read;
	uint32 iid_ptr;
	IMAGE_SECTION_HEADER *section = NULL;
	struct buffer fake_iat;
	uint32 base = out_buf->pos;
	uint32 codebase = pf->opt_hdr.code_base;
	int i = 0;
	uint32 dll_len_sum = 0;

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

	printf("Image Import Desc. is located at file offset %08x\n", iid_ptr);

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

	init_buffer(&fake_iat, 1024);

	iid_iter = iid;
	/* foreach IID */
	while (iid_iter->name)
	{
		uint32 offset = 0;
		int c = 1;
		byte *p = out_buf->p;
		uint32 dll_offset_pos = out_buf->pos; /* save pos for later */

		/* put garbage now - will be modified later */
		add_buffer(out_buf, "\xff\xff\xff\xff", 4);

		/* calculate offset to original IAT */
		offset = iid_iter->import_addr_table - pf->opt_hdr.code_base;
		add_buffer(out_buf, &offset, 4);

		/* add original function names */
		while (1)
		{
			offset = *(uint32 *)(p + iid_iter->import_name_table - codebase);
			if (!offset)
				break;

			c = 1;
			add_buffer(out_buf, &c, 1);

			/* skip ordinal */
			offset += 2;
			add_buffer(out_buf, p + offset - codebase,
				strlen((const char *)p + offset - codebase) + 1);

			iid_iter->import_name_table += 4;
		}

		c = 0;
		add_buffer(out_buf, &c, 1);

		/* working fake IAT from here */
		{
			char *dll_name = (char *)(p + iid_iter->name - codebase);
			uint32 dll_offset = pf->opt_hdr.data_dir[DIR_IMPORT].size + dll_len_sum;

			add_buffer_at(&fake_iat, dll_name, strlen(dll_name) + 1, dll_offset);
			add_buffer_at(out_buf, &dll_offset, 4, dll_offset_pos);

			dll_len_sum += strlen(dll_name) + 1;
		}

		++i;
		++iid_iter;
	} /* foreach IID */

	round_up_buffer(out_buf, 4);
	base = out_buf->pos;
	i = 0;

	/* start over for pass 2 */
	iid_iter = iid;
	while (iid_iter->name)
	{
		byte *p = out_buf->p;
		char *dll_name = (char *)(p + iid_iter->name - codebase);

		iid_iter->forward_chain = 0;
		iid_iter->import_name_table = 0;
		iid_iter->timestamp = 0;
		iid_iter->import_addr_table = 0;

		if (!stricmp(dll_name, kernel32))
		{
			uint32 iat_base = pf->opt_hdr.data_dir[DIR_IMPORT].size + dll_len_sum;
			uint32 iat_value = base + iat_base + sizeof(k32_funcs);

			/* IAT */
			add_buffer_at(&fake_iat, &iat_value, 4, iat_base);
			iat_value += 14;
			add_buffer_at(&fake_iat, &iat_value, 4, iat_base + 4);
			iat_value += 16;
			add_buffer_at(&fake_iat, &iat_value, 4, iat_base + 8);

			/* function names */
			add_buffer_at(&fake_iat, k32_funcs[0], 14, iat_base + 12);
			add_buffer_at(&fake_iat, k32_funcs[1], 16, iat_base + 12 + 14);
			add_buffer_at(&fake_iat, k32_funcs[2], 14, iat_base + 12 + 14 + 16);

			iid_iter->import_addr_table = base + dll_len_sum;
		}

		add_buffer(&fake_iat, iid_iter, sizeof(IMAGE_IMPORT_DESC));

		++iid_iter;
	}

	/* FIXME: so ugly and dirty... */
	fake_iat.pos += dll_len_sum + sizeof(k32_funcs) + 12 + 14 + 16 + 18;

	round_up_buffer(&fake_iat, 4);
	add_buffer(out_buf, fake_iat.p, fake_iat.pos);

	destroy_buffer(&fake_iat);

	if (iid)
		free(iid);

	return 1;
}