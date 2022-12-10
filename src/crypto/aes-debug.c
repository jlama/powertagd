/*
 * aes-debug.c
 *
 * derived from wpa_supplicant
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "aes.h"

#ifdef AES_DEBUG

int aes_debug_level = MSG_EXCESSIVE;
int aes_debug_show_keys = 1;
int aes_debug_timestamp = 1;


void aes_debug_print_timestamp(void)
{
	struct timeval tv;

	if (!aes_debug_timestamp)
		return;

	gettimeofday(&tv, NULL);
	printf("%ld.%06u: ", (long) tv.tv_sec, (unsigned int) tv.tv_usec);
}


void aes_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= aes_debug_level) {
		aes_debug_print_timestamp();
		vprintf(fmt, ap);
		printf("\n");
	}
	va_end(ap);
}


static void _aes_hexdump(int level, const char *title, const uint8_t *buf,
			 size_t len, int show)
{
	size_t i;

	if (level < aes_debug_level)
		return;

	aes_debug_print_timestamp();
	printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
	if (buf == NULL) {
		printf(" [NULL]");
	} else if (show) {
		for (i = 0; i < len; i++)
			printf(" %02x", buf[i]);
	} else {
		printf(" [REDACTED]");
	}
	printf("\n");
}


void aes_hexdump(int level, const char *title, const void *buf, size_t len)
{
	_aes_hexdump(level, title, buf, len, 1);
}


void aes_hexdump_key(int level, const char *title, const void *buf, size_t len)
{
	_aes_hexdump(level, title, buf, len, aes_debug_show_keys);
}


static void _aes_hexdump_ascii(int level, const char *title, const void *buf,
			       size_t len, int show)
{
	size_t i, llen;
	const uint8_t *pos = buf;
	const size_t line_len = 16;

	if (level < aes_debug_level)
		return;

	aes_debug_print_timestamp();
	if (!show) {
		printf("%s - hexdump_ascii(len=%lu): [REDACTED]\n",
		       title, (unsigned long) len);
		return;
	}
	if (buf == NULL) {
		printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
		       title, (unsigned long) len);
		return;
	}
	printf("%s - hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
	while (len) {
		llen = len > line_len ? line_len : len;
		printf("    ");
		for (i = 0; i < llen; i++)
			printf(" %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			printf("   ");
		printf("   ");
		for (i = 0; i < llen; i++) {
			if (isprint(pos[i]))
				printf("%c", pos[i]);
			else
				printf("_");
		}
		for (i = llen; i < line_len; i++)
			printf(" ");
		printf("\n");
		pos += llen;
		len -= llen;
	}
}


void aes_hexdump_ascii(int level, const char *title, const void *buf,
		       size_t len)
{
	_aes_hexdump_ascii(level, title, buf, len, 1);
}


void aes_hexdump_ascii_key(int level, const char *title, const void *buf,
			   size_t len)
{
	_aes_hexdump_ascii(level, title, buf, len, aes_debug_show_keys);
}

#endif
