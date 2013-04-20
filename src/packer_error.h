#ifndef __PACKER_ERROR_H
#define __PACKER_ERROR_H

#define PACKER_INVALID_FORMAT	1

struct packer_info;
void packer_set_error(struct packer_info *pi, int err);

#endif