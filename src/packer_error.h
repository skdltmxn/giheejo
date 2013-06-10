#ifndef __PACKER_ERROR_H
#define __PACKER_ERROR_H

#define PACKER_INVALID_FORMAT	1
#define PACKER_NO_MEMORY		2
#define PACKER_COMPRESS_FAILED	3

void packer_set_error(struct packer_info *pi, int err);

#endif