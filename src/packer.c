#include <stdlib.h>
#include "types.h"
#include "packer_info.h"
#include "config.h"
#include "file.h"

#if defined(_WIN32) || defined(_WIN64)
#include "win/pe_packer.h"
#endif

void packer_set_error(struct packer_info *pi, int err)
{
	pi->err = err;
}

int pack_file(config_t *conf)
{
	struct file_info input_file;
	struct packer_info packer;
	int pack_result;

	/* open file */
	input_file.fp = fopen(conf->input_filename, "rb");
	if (!input_file.fp)
	{
		printf("[-] Input file %s not found\n", conf->input_filename);
		return 0;
	}

#ifdef GIJ_WIN
	/* Windows PE format */
	pack_result = pe_pack(&input_file, &packer);
#endif

	if (!pack_result)
	{
		printf("[-] Error occurred %d\n", packer.err);
	}

#ifdef GIJ_WIN
	pe_destroy(&input_file);
#endif

	fclose(input_file.fp);
	return 1;
}