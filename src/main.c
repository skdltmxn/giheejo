#include <stdio.h>
#include "types.h"
#include "config.h"
#include "packer.h"

static void usage(const char *me)
{
	printf("********************************************\n");
	printf("              G.IHee.Jo Packer              \n");
	printf("********************************************\n");
	printf("\n[Usage] %s input_file output_file\n", me);
}

static int parse_option(int argc, char **argv, config_t *conf)
{
	char **p = argv + 1;

	if (argc < 3)
	{
		usage(argv[0]);
		return 0;
	}

	conf->input_filename = *p++;
	conf->output_filename = *p;

	return 1;
}

int main(int argc, char **argv)
{
	config_t conf;

	if (!parse_option(argc, argv, &conf))
		return 1;

	pack_file(&conf);
	
	return 0;
}