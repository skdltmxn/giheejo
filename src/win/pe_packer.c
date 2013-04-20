#include "../types.h"
#include "../file.h"
#include "../packer_info.h"
#include "../packer_error.h"
#include "pe_packer.h"
#include "pe.h"

int pe_pack(struct file_info *f, struct packer_info *pi)
{
	uint32 filesize = file_size(f);

	if (filesize < 0x3c)
	{
		packer_set_error(pi, PACKER_INVALID_FORMAT);
		return 0;
	}

	return 1;
}