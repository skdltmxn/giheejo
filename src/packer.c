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

	input_file.fp = fopen(conf->input_filename, "rb");
	if (!input_file.fp)
	{
		printf("[-] Input file %s not found\n", conf->input_filename);
		return 0;
	}

#if defined(_WIN32) || defined(_WIN64)
	pack_result = pe_pack(&input_file, &packer);
#endif

	if (!pack_result)
	{
		printf("[-] Error occurred %d\n", packer.err);
	}

	fclose(input_file.fp);
	return 1;
}