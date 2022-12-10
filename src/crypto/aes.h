/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES_FULL_UNROLL
#define AES_SMALL_TABLES
#define AES_BLOCK_SIZE 16

#include "aes-common.h"
#include "aes-internal.h"
#include "aes-debug.h"

void *aes_encrypt_init(const uint8_t *key, size_t len);
void aes_encrypt(void *ctx, const uint8_t *plain, uint8_t *crypt);
void aes_encrypt_deinit(void *ctx);

void *aes_decrypt_init(const uint8_t *key, size_t len);
void aes_decrypt(void *ctx, const uint8_t *crypt, uint8_t *plain);
void aes_decrypt_deinit(void *ctx);

int aes_wrap(const uint8_t *kek, size_t kek_len, int n, const uint8_t *plain, uint8_t *cipher);
int aes_unwrap(const uint8_t *kek, size_t kek_len, int n, const uint8_t *cipher, uint8_t *plain);

int aes_128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out);

int aes_ctr_encrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce,
                    uint8_t *data, size_t data_len);
int aes_128_ctr_encrypt(const uint8_t *key, const uint8_t *nonce,
                        uint8_t *data, size_t data_len);

int aes_128_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                        uint8_t *data, size_t data_len);
int aes_128_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                        uint8_t *data, size_t data_len);

int aes_ccm_ae(const uint8_t *key, size_t key_len, const uint8_t *nonce,
               size_t M, const uint8_t *plain, size_t plain_len,
               const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *auth);
int aes_ccm_ad(const uint8_t *key, size_t key_len, const uint8_t *nonce,
               size_t M, const uint8_t *crypt, size_t crypt_len,
               const uint8_t *aad, size_t aad_len, const uint8_t *auth,
               uint8_t *plain);

#ifdef __cplusplus
}
#endif

#endif /* AES_H */
