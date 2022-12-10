/*
 * aes-common.h
 *
 * Copyright (c) 2014, Michael Clark <mclark@meta.sg>
 *
 * derived from wpa_supplicant
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_COMMON_H
#define AES_COMMON_H

#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* byte order */

#if defined(__linux__) || defined(__GLIBC__)
#include <endian.h>
#include <byteswap.h>
#endif /* defined(__linux__) || defined(__GLIBC__) */

#if defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/endian.h>
#define __BYTE_ORDER	_BYTE_ORDER
#define __LITTLE_ENDIAN	_LITTLE_ENDIAN
#define __BIG_ENDIAN	_BIG_ENDIAN
#endif /* defined(__FreeBSD__) || defined(__NetBSD__) ||
        * defined(__DragonFly__) || defined(__OpenBSD__) */

#ifdef __APPLE__
#include <sys/types.h>
#include <machine/endian.h>
#define __BYTE_ORDER    BYTE_ORDER
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BIG_ENDIAN    BIG_ENDIAN
#endif /* __APPLE__ */


/* byte swap macros */

#ifndef bswap_16
#define bswap_16(a) ((((uint16_t) (a) & 0xff00) >> 8) | \
                     (((uint16_t) (a) & 0x00ff) << 8))
#endif

#ifndef bswap_32
#define bswap_32(a) __builtin_bswap32(a)
#endif

#ifndef bswap_64
#define bswap_64(a) __builtin_bswap64(a)
#endif


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __ENDIAN_LITTLE__ 1 /* OpenCL */
#define le_to_host16(n) (n)
#define host_to_le16(n) (n)
#define be_to_host16(n) bswap_16(n)
#define host_to_be16(n) bswap_16(n)
#define le_to_host32(n) (n)
#define host_to_le32(n) (n)
#define be_to_host32(n) bswap_32(n)
#define host_to_be32(n) bswap_32(n)
#define le_to_host64(n) (n)
#define host_to_le64(n) (n)
#define be_to_host64(n) bswap_64(n)
#define host_to_be64(n) bswap_64(n)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#define le_to_host32(n) bswap_32(n)
#define host_to_le32(n) bswap_32(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#define le_to_host64(n) bswap_64(n)
#define host_to_le64(n) bswap_64(n)
#define be_to_host64(n) (n)
#define host_to_be64(n) (n)
#else
#error Could not determine CPU byte order
#endif


/* unaligned memory accesses */

static inline uint16_t AES_GET_BE16(const uint8_t *a)
{
	return (a[0] << 8) | a[1];
}

static inline void AES_PUT_BE16(uint8_t *a, uint16_t val)
{
	a[0] = val >> 8;
	a[1] = val & 0xff;
}

static inline uint16_t AES_GET_LE16(const uint8_t *a)
{
	return (a[1] << 8) | a[0];
}

static inline void AES_PUT_LE16(uint8_t *a, uint16_t val)
{
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

#if 0
static inline uint32_t AES_GET_BE24(const uint8_t *a)
{
	return (a[0] << 16) | (a[1] << 8) | a[2];
}


static inline void AES_PUT_BE24(uint8_t *a, uint32_t val)
{
	a[0] = (val >> 16) & 0xff;
	a[1] = (val >> 8) & 0xff;
	a[2] = val & 0xff;
}
#endif

static inline uint32_t AES_GET_BE32(const uint8_t *a)
{
	return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void AES_PUT_BE32(uint8_t *a, uint32_t val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

static inline uint32_t AES_GET_LE32(const uint8_t *a)
{
	return (a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
}

static inline void AES_PUT_LE32(uint8_t *a, uint32_t val)
{
	a[3] = (val >> 24) & 0xff;
	a[2] = (val >> 16) & 0xff;
	a[1] = (val >> 8) & 0xff;
	a[0] = val & 0xff;
}

static inline uint64_t AES_GET_BE64(const uint8_t *a)
{
	return (((uint64_t) a[0]) << 56) | (((uint64_t) a[1]) << 48) |
            (((uint64_t) a[2]) << 40) | (((uint64_t) a[3]) << 32) |
            (((uint64_t) a[4]) << 24) | (((uint64_t) a[5]) << 16) |
            (((uint64_t) a[6]) << 8) | ((uint64_t) a[7]);
}

static inline void AES_PUT_BE64(uint8_t *a, uint64_t val)
{
	a[0] = val >> 56;
	a[1] = val >> 48;
	a[2] = val >> 40;
	a[3] = val >> 32;
	a[4] = val >> 24;
	a[5] = val >> 16;
	a[6] = val >> 8;
	a[7] = val & 0xff;
}

static inline uint64_t AES_GET_LE64(const uint8_t *a)
{
	return (((uint64_t) a[7]) << 56) | (((uint64_t) a[6]) << 48) |
            (((uint64_t) a[5]) << 40) | (((uint64_t) a[4]) << 32) |
            (((uint64_t) a[3]) << 24) | (((uint64_t) a[2]) << 16) |
            (((uint64_t) a[1]) << 8) | ((uint64_t) a[0]);
}

static inline void AES_PUT_LE64(uint8_t *a, uint64_t val)
{
	a[7] = val >> 56;
	a[6] = val >> 48;
	a[5] = val >> 40;
	a[4] = val >> 32;
	a[3] = val >> 24;
	a[2] = val >> 16;
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

#endif /* AES_COMMON_H */
