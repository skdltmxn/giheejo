#ifndef __PE_PACKER_H
#define __PE_PACKER_H

extern int pe_iat(struct file_info *in, struct packer_info *pi, struct buffer *out_buf,
																struct buffer *fake_iat);
extern int pe_iat2(struct packer_info *pi, uint32 base, struct buffer *fake_iat);

extern int pe_pack(struct file_info *oi, struct packer_info *pi, config_t *conf);
extern void pe_destroy(struct file_info *fi);

#endif