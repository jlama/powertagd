/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CRC_CCITT_H
#define _LINUX_CRC_CCITT_H

#include <stddef.h>
#include <stdint.h>

extern const uint16_t crc_ccitt_table[256];
extern const uint16_t crc_ccitt_false_table[256];

extern uint16_t crc_ccitt(uint16_t crc, const uint8_t *buf, size_t len);
extern uint16_t crc_ccitt_false(uint16_t crc, const uint8_t *buf, size_t len);

static inline uint16_t crc_ccitt_byte(uint16_t crc, const uint8_t c)
{
	return (crc >> 8) ^ crc_ccitt_table[(crc ^ c) & 0xff];
}

static inline uint16_t crc_ccitt_false_byte(uint16_t crc, const uint8_t c)
{
	return (crc << 8) ^ crc_ccitt_false_table[(crc >> 8) ^ c];
}

#endif /* _LINUX_CRC_CCITT_H */
