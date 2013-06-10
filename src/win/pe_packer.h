#ifndef __PE_PACKER_H
#define __PE_PACKER_H

extern int pe_iat(struct file_info *in, struct packer_info *pi);

extern int pe_pack(struct file_info *oi, struct packer_info *pi, config_t *conf);
extern void pe_destroy(struct file_info *fi);

#endif