#include "../types.h"
#include "../file.h"
#include "pe.h"
#include "../packer_info.h"

static int pe_iid(struct file_info *in, struct packer_info *pi)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;
	IMAGE_IMPORT_DESC iid;
	uint32 iid_ptr;
	IMAGE_SECTION_HEADER *section = NULL;

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

	while (1)
	{
		size_t read;
		read = fread(&iid, sizeof(IMAGE_IMPORT_DESC), 1, in->fp);
		if (read != 1)
		{
			packer_set_error(pi, PACKER_INVALID_FORMAT);
			return 0;
		}

		/* no more entry */
		if (!iid.import_name_table)
			break;

		printf("Import Name Table is at %08x in RVA\n", iid.import_name_table);
	}

	return 1;
}

int pe_iat(struct file_info *in, struct packer_info *pi)
{
	struct pe_format *pf = (struct pe_format *)in->file_format;

	/* no import is not right */
	if (pf->opt_hdr.nr_data_dir < DIR_IMPORT)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	pe_iid(in, pi);

	return 1;
}