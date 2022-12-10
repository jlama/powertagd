/*
 * AES encrypt_block
 *
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "aes.h"

/**
 * aes_128_encrypt_block - Perform one AES 128-bit block operation
 * @key: Key for AES
 * @in: Input data (16 bytes)
 * @out: Output of the AES block operation (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int aes_128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
	void *ctx;
	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	aes_encrypt(ctx, in, out);
	aes_encrypt_deinit(ctx);
	return 0;
}
