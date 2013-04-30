#ifndef __TYPE_H
#define __TYPE_H

/* Shut visual studio up */
#pragma warning(disable:4996)

/* Primitive types */
typedef unsigned char		byte;
typedef unsigned short		uint16;
typedef unsigned int		uint32;
typedef unsigned long long	uint64;

typedef short		int16;
typedef int			int32;
typedef long long	int64;

/* Boolean */
typedef int		bool;
#define true	(1 == 1)
#define false	!true

/* NULL */
#ifndef NULL
#define NULL 0
#endif

/* inline keyword */
#if defined(_MSC_VER)
#define inline	__inline
#elif defined(__GNUC__)
#define inline	__inline__
#endif

/* multi-platform support */

#if defined(_WIN32) || defined(_WIN64)
#define	GIJ_WIN
#endif

#endif