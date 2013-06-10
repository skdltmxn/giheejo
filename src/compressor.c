#include "types.h"
#include "compressor.h"
#include "lzo/lzo1x.h"

int compress(byte *src, const uint32 src_len, byte *dst, uint32 *dst_len)
{
	byte work_mem[LZO1X_999_MEM_COMPRESS];

	return lzo1x_999_compress(src, src_len, dst, (lzo_uint *)dst_len, work_mem);
}