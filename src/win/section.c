#include <string.h>
#include "../types.h"
#include "../file.h"
#include "pe.h"
#include "../packer_info.h"

IMAGE_SECTION_HEADER *get_containing_section(struct pe_format *pf, uint32 rva)
{
	int i;
	IMAGE_SECTION_HEADER *ret = NULL;

	if (pf->img_hdr.nr_sections == 1)
		return pf->section_hdr;

	for (i = 1; i < pf->img_hdr.nr_sections; ++i)
	{
		if (pf->section_hdr[i].virtual_addr > rva)
		{
			ret = pf->section_hdr + (i - 1);
			break;
		}
	}

	return ret;
}

IMAGE_SECTION_HEADER *find_section(struct pe_format *pf, const char *name)
{
	int i;

	for (i = 0; i < pf->img_hdr.nr_sections; ++i)
	{
		if (!strcmp(pf->section_hdr[i].section_name, name))
			return &pf->section_hdr[i];
	}

	return NULL;
}