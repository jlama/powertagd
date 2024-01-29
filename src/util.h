#ifndef UTIL_H
#define UTIL_H

#include <sys/time.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static inline void u16_to_mem(uint16_t a, uint8_t *buf)
{
	buf[0] = a & 0xFF;
	buf[1] = a >> 8;
}

static inline uint16_t u16_from_mem(const uint8_t *buf)
{
	return ((uint16_t)buf[1] << 8) | buf[0];
}

static inline void u32_to_mem(uint32_t a, uint8_t *buf)
{
	buf[0] = a & 0xFF;
	buf[1] = a >> 8;
	buf[2] = a >> 16;
	buf[3] = a >> 24;
}

static inline uint32_t u24_from_mem(const uint8_t *buf)
{
	return (uint32_t)buf[0] | (buf[1] << 8) | (buf[2] << 16);
}

static inline uint32_t u32_from_mem(const uint8_t *buf)
{
	return (uint32_t)buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static inline void u64_to_mem(uint64_t a, uint8_t *buf)
{
	u32_to_mem(a & 0xFFFF, buf);
	u32_to_mem(a >> 32,    buf+4);
}

static inline uint64_t u40_from_mem(const uint8_t *buf)
{
	return (uint64_t)u32_from_mem(buf) | (uint64_t)buf[4] << 32;
}

static inline uint64_t u48_from_mem(const uint8_t *buf)
{
	return (uint64_t)u32_from_mem(buf) | (uint64_t)buf[4] << 32 |
	       (uint64_t)buf[5] << 40;
}

static inline uint64_t u56_from_mem(const uint8_t *buf)
{
	return (uint64_t)u48_from_mem(buf) | (uint64_t)buf[6] << 48;
}

static inline uint64_t u64_from_mem(const uint8_t *buf)
{
	return ((uint64_t)u32_from_mem(buf+4) << 32 | u32_from_mem(buf));
}

#ifndef timespecsub
#define timespecsub(a, b, res) do { \
	(res)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
	(res)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec; \
	if ((res)->tv_nsec < 0) { \
		(res)->tv_sec--; \
		(res)->tv_nsec += 1000000000L; \
	} \
} while (0)
#endif

/* Return the time difference in milliseconds between two timespecs. */
static inline int timespec_diff(struct timespec *start, struct timespec *end)
{
	struct timespec diff;
	timespecsub(end, start, &diff);

	return (diff.tv_sec * 1000) + (diff.tv_nsec / 1e6);
}

static inline int hex2int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * Convert a hex string to byte array.
 * On success, return the number of bytes converted.
 * On error, return 0.
 */
static size_t hex2bin(const char *s, uint8_t *buf, size_t bufsz)
{
	assert(buf != NULL && bufsz > 0);

	size_t slen = strlen(s);
	if (slen < 2)
		return 0;

	// Skip '0x' prefix if present.
	if (s[0] == '0' && s[1] == 'x')
		s += 2, slen -= 2;
	// Make sure we have an even number of chars and the output buffer is
	// big enough.
	if (slen % 2 != 0 || slen / 2 > bufsz)
		return 0;

	size_t nb = 0;
	while (1) {
		if (s[0] == '\0')
			break;

		int c1 = hex2int(s[0]);
		int c2 = hex2int(s[1]);
		if (c1 == -1 || c2 == -1)
			return 0;

		buf[nb++] = (c1 * 16) + c2;
		s += 2;
	}
	return nb;
}

static const char *key2str(uint8_t k[16])
{
	static const char hex[] = "0123456789abcdef";
	static char str[16*2+1];

	char *p = str;
	for (int i = 0; i < 16; i++) {
		p[0] = hex[k[i] >> 4];
		p[1] = hex[k[i] & 0xf];
		p += 2;
	}
	*p = '\0';
	return str;
}

#ifdef __linux__

// glibc implements arc4random functions since version 2.36
#if defined(__GLIBC__) && __GLIBC_MINOR__ < 36
#include <sys/random.h>

static void arc4random_buf(void *buf, size_t nbytes)
{
	ssize_t r = getrandom(buf, nbytes, 0);
	assert(r == nbytes);
}

static uint32_t arc4random(void)
{
	uint32_t v;
	arc4random_buf(&v, sizeof(v));
	return v;
}
#endif

static const char *getprogname(void)
{
	extern char *__progname;
	return __progname;
}
#endif

#endif
