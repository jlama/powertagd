/*
 * crypto module tests
 * Copyright (c) 2014-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <stdbool.h>
#include "aes.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef uint8_t u8;

int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, u8 *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	u8 *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

static int test_cbc(void)
{
	struct cbc_test_vector {
		u8 key[16];
		u8 iv[16];
		u8 plain[32];
		u8 cipher[32];
		size_t len;
	} vectors[] = {
		{
			{ 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
			  0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 },
			{ 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
			  0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 },
			"Single block msg",
			{ 0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8,
			  0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a },
			16
		},
		{
			{ 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
			  0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a },
			{ 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
			  0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 },
			{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
			{ 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a,
			  0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
			  0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9,
			  0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 },
			32
		}
	};
	int ret = 0;
	u8 *buf;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		struct cbc_test_vector *tv = &vectors[i];

		buf = malloc(tv->len);
		if (buf == NULL) {
			ret++;
			break;
		}

		memcpy(buf, tv->plain, tv->len);
		if (aes_128_cbc_encrypt(tv->key, tv->iv, buf, tv->len) ||
		    memcmp(buf, tv->cipher, tv->len) != 0) {
			printf("Error: AES-CBC encrypt %d failed", i);
			ret++;
		}

		memcpy(buf, tv->cipher, tv->len);
		if (aes_128_cbc_decrypt(tv->key, tv->iv, buf, tv->len) ||
		    memcmp(buf, tv->plain, tv->len) != 0) {
			printf("Error: AES-CBC decrypt %d failed", i);
			ret++;
		}

		free(buf);
	}

	return ret;
}


static int test_ecb(void)
{
	struct ecb_test_vector {
		char *key;
		char *plaintext;
		char *ciphertext;
	} vectors[] = {
		/* CAVS 11.1 - ECBGFSbox128.rsp */
		{
			"00000000000000000000000000000000",
			"f34481ec3cc627bacd5dc3fb08f273e6",
			"0336763e966d92595a567cc9ce537f5e"
		},
		{
			"00000000000000000000000000000000",
			"9798c4640bad75c7c3227db910174e72",
			"a9a1631bf4996954ebc093957b234589"
		},
		{
			"00000000000000000000000000000000",
			"96ab5c2ff612d9dfaae8c31f30c42168",
			"ff4f8391a6a40ca5b25d23bedd44a597"
		},
		{
			"00000000000000000000000000000000",
			"6a118a874519e64e9963798a503f1d35",
			"dc43be40be0e53712f7e2bf5ca707209"
		},
		{
			"00000000000000000000000000000000",
			"cb9fceec81286ca3e989bd979b0cb284",
			"92beedab1895a94faa69b632e5cc47ce"
		},
		{
			"00000000000000000000000000000000",
			"b26aeb1874e47ca8358ff22378f09144",
			"459264f4798f6a78bacb89c15ed3d601"
		},
		{
			"00000000000000000000000000000000",
			"58c8e00b2631686d54eab84b91f0aca1",
			"08a4e2efec8a8e3312ca7460b9040bbf"
		},
		/* CAVS 11.1 - ECBKeySbox128.rsp */
		{
			"10a58869d74be5a374cf867cfb473859",
			"00000000000000000000000000000000",
			"6d251e6944b051e04eaa6fb4dbf78465"
		},
		{
			"caea65cdbb75e9169ecd22ebe6e54675",
			"00000000000000000000000000000000",
			"6e29201190152df4ee058139def610bb",
		}
	};
	int ret = 0;
	unsigned int i;
	u8 key[16], plain[16], cipher[16], out[16];

	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		struct ecb_test_vector *tv = &vectors[i];

		if (hexstr2bin(tv->key, key, sizeof(key)) ||
		    hexstr2bin(tv->plaintext, plain, sizeof(plain)) ||
		    hexstr2bin(tv->ciphertext, cipher, sizeof(cipher))) {
			printf("Error: Invalid AES-ECB test vector %u", i);
			ret++;
			continue;
		}

		if (aes_128_encrypt_block(key, plain, out) < 0 ||
		    memcmp(out, cipher, 16) != 0) {
			printf("Error: AES-ECB encrypt %u failed", i);
			ret++;
		}
	}

	if (!ret)
		printf("AES ECB mode test cases passed\n");

	return ret;
}


static int test_key_wrap(void)
{
	int ret = 0;

	/* RFC 3394 - Test vector 4.1 */
	u8 kek41[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	u8 plain41[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	u8 crypt41[] = {
		0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
	};
	/* RFC 3394 - Test vector 4.2 */
	u8 kek42[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};
	u8 plain42[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	u8 crypt42[] = {
		0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
		0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
		0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D
	};
	/* RFC 3394 - Test vector 4.3 */
	u8 kek43[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	u8 plain43[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	u8 crypt43[] = {
		0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
		0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
		0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
	};
	/* RFC 3394 - Test vector 4.4 */
	u8 kek44[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};
	u8 plain44[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	};
	u8 crypt44[] = {
		0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
		0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
		0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
		0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2
	};
	/* RFC 3394 - Test vector 4.5 */
	u8 kek45[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	u8 plain45[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	};
	u8 crypt45[] = {
		0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
		0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
		0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
		0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1,
	};
	/* RFC 3394 - Test vector 4.6 */
	u8 kek46[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	u8 plain46[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	u8 crypt46[] = {
		0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
		0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
		0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
		0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
		0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21
	};
	u8 result[40];

	printf("RFC 3394 - Test vector 4.1\n");
	if (aes_wrap(kek41, sizeof(kek41), sizeof(plain41) / 8, plain41, result)) {
		printf("Error: AES-WRAP-128 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt41, sizeof(crypt41)) != 0) {
		printf("Error: AES-WRAP-128 failed\n");
		ret++;
	}
	if (aes_unwrap(kek41, sizeof(kek41), sizeof(plain41) / 8, crypt41, result)) {
		printf("Error: AES-UNWRAP-128 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain41, sizeof(plain41)) != 0) {
		printf("Error: AES-UNWRAP-128 failed\n");
		ret++;
	}

	printf("RFC 3394 - Test vector 4.2\n");
	if (aes_wrap(kek42, sizeof(kek42), sizeof(plain42) / 8, plain42, result)) {
		printf("Error: AES-WRAP-192 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt42, sizeof(crypt42)) != 0) {
		printf("Error: AES-WRAP-192 failed\n");
		ret++;
	}
	if (aes_unwrap(kek42, sizeof(kek42), sizeof(plain42) / 8, crypt42, result)) {
		printf("Error: AES-UNWRAP-192 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain42, sizeof(plain42)) != 0) {
		printf("Error: AES-UNWRAP-192 failed\n");
		ret++;
	}

	printf("RFC 3394 - Test vector 4.3\n");
	if (aes_wrap(kek43, sizeof(kek43), sizeof(plain43) / 8, plain43, result)) {
		printf("Error: AES-WRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt43, sizeof(crypt43)) != 0) {
		printf("Error: AES-WRAP-256 failed\n");
		ret++;
	}
	if (aes_unwrap(kek43, sizeof(kek43), sizeof(plain43) / 8, crypt43, result)) {
		printf("Error: AES-UNWRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain43, sizeof(plain43)) != 0) {
		printf("Error: AES-UNWRAP-256 failed\n");
		ret++;
	}

	printf("RFC 3394 - Test vector 4.4\n");
	if (aes_wrap(kek44, sizeof(kek44), sizeof(plain44) / 8, plain44, result)) {
		printf("Error: AES-WRAP-192 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt44, sizeof(crypt44)) != 0) {
		printf("Error: AES-WRAP-192 failed\n");
		ret++;
	}
	if (aes_unwrap(kek44, sizeof(kek44), sizeof(plain44) / 8, crypt44, result)) {
		printf("Error: AES-UNWRAP-192 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain44, sizeof(plain44)) != 0) {
		printf("Error: AES-UNWRAP-192 failed\n");
		ret++;
	}

	printf("RFC 3394 - Test vector 4.5\n");
	if (aes_wrap(kek45, sizeof(kek45), sizeof(plain45) / 8, plain45,
		     result)) {
		printf("Error: AES-WRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt45, sizeof(crypt45)) != 0) {
		printf("Error: AES-WRAP-256 failed\n");
		ret++;
	}
	if (aes_unwrap(kek45, sizeof(kek45), sizeof(plain45) / 8, crypt45,
		       result)) {
		printf("Error: AES-UNWRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain45, sizeof(plain45)) != 0) {
		printf("Error: AES-UNWRAP-256 failed\n");
		ret++;
	}

	printf("RFC 3394 - Test vector 4.6\n");
	if (aes_wrap(kek46, sizeof(kek46), sizeof(plain46) / 8, plain46,
		     result)) {
		printf("Error: AES-WRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, crypt46, sizeof(crypt46)) != 0) {
		printf("Error: AES-WRAP-256 failed\n");
		ret++;
	}
	if (aes_unwrap(kek46, sizeof(kek46), sizeof(plain46) / 8, crypt46,
		       result)) {
		printf("Error: AES-UNWRAP-256 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain46, sizeof(plain46)) != 0) {
		printf("Error: AES-UNWRAP-256 failed\n");
		ret++;
	}

	if (!ret)
		printf("AES key wrap/unwrap test cases passed\n");

	return ret;
}


static int test_aes_ctr(void)
{
	int res = 0;

	/* CTR-AES*.Encrypt test vectors from NIST SP 800-38a */
	const u8 key128[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	const u8 counter128[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};
	const u8 plain128[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	const u8 cipher128[] = {
		0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
		0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
		0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
		0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
		0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
		0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
		0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
		0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
	};
	const u8 key192[] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	};
	const u8 counter192[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};
	const u8 plain192[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	const u8 cipher192[] = {
		0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
		0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
		0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef,
		0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94,
		0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70,
		0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7,
		0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58,
		0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50
	};
	const u8 key256[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
	const u8 counter256[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
	};
	const u8 plain256[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	const u8 cipher256[] = {
		0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
		0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
		0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
		0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
		0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
		0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
		0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
		0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
	};
	size_t len;
	u8 *tmp;

	printf("CTR-AES128.Encrypt\n");
	len = sizeof(plain128);
	tmp = malloc(len);
	if (!tmp)
		return -1;
	memcpy(tmp, plain128, len);
	if (aes_ctr_encrypt(key128, sizeof(key128), counter128, tmp, len) < 0) {
		printf("Error: aes_ctr_encrypt() failed\n");
		res = -1;
	} else if (memcmp(tmp, cipher128, len) != 0) {
		printf("Error: CTR-AES128.Encrypt test vector did not match\n");
		res = -1;
	}
	free(tmp);

	printf("CTR-AES192.Encrypt\n");
	len = sizeof(plain192);
	tmp = malloc(len);
	if (!tmp)
		return -1;
	memcpy(tmp, plain192, len);
	if (aes_ctr_encrypt(key192, sizeof(key192), counter192, tmp, len) < 0) {
		printf("Error: aes_ctr_encrypt() failed\n");
		res = -1;
	} else if (memcmp(tmp, cipher192, len) != 0) {
		printf("Error: CTR-AES192.Encrypt test vector did not match\n");
		res = -1;
	}
	free(tmp);

	printf("CTR-AES256.Encrypt\n");
	len = sizeof(plain256);
	tmp = malloc(len);
	if (!tmp)
		return -1;
	memcpy(tmp, plain256, len);
	if (aes_ctr_encrypt(key256, sizeof(key256), counter256, tmp, len) < 0) {
		printf("Error: aes_ctr_encrypt() failed\n");
		res = -1;
	} else if (memcmp(tmp, cipher256, len) != 0) {
		printf("Error: CTR-AES256.Encrypt test vector did not match\n");
		res = -1;
	}
	free(tmp);

	return res;
}

static inline void u32_to_mem(uint32_t a, uint8_t *buf)
{
	buf[0] = a & 0xFF;
	buf[1] = a >> 8;
	buf[2] = a >> 16;
	buf[3] = a >> 24;
}

static void zgp_compute_nonce(uint32_t srcid, uint32_t frame_counter,
    bool is_rx, uint8_t nonce[13])
{
	/* For outgoing frames, the first 4 bytes shall be zero. */
	if (is_rx)
		u32_to_mem(srcid, nonce);
	else
		u32_to_mem(0, nonce);
	u32_to_mem(srcid, nonce+4);

	/* Append frame Counter bytes represented as little endian */
	u32_to_mem(frame_counter, nonce+8);
	/* Security control byte. Fixed value. */
	nonce[12] = 0x05;
}

static int test_aes_ccm_encrypt(void)
{
	uint8_t key1[16] = {
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
		0xC8, 0xC9, 0xCa, 0xCb, 0xCc, 0xCd, 0xCe, 0xCf,
	};
	uint8_t key2[16] = {
		0x2b, 0x38, 0x9d, 0x32, 0xa9, 0xf5, 0x3e, 0x67,
		0x91, 0x0a, 0x2c, 0x47, 0x9e, 0x12, 0xa9, 0x8d,
	};
	uint8_t key3[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};

	struct ccm_test_vector {
		uint8_t *key;
		uint8_t aad[32]; // AddAuthData
		uint8_t aad_len;
		uint8_t nonce[13];
		uint8_t plaintext[16];
		uint8_t plaintext_len;

		uint32_t expected_U;
		uint8_t expected_cipher[16];
	} vectors[] = {
		{ /* ZigBee Green Power TX frame with SecurityLevel = 0x2 (A.1.5.5.3) */
			.key = key1,
			.aad = {0x8e, 0x10, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x20},
			.aad_len = 11,
			.nonce = {0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x05},
			.plaintext = {0},
			.plaintext_len = 0,
			.expected_U = 0x79b0c00f,
		},
		{ /* ZigBee Green Power TX frame with SecurityLevel = 0x3 (A.1.5.5.4) */
			.key = key1,
			.aad = {0x8c, 0x18, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00},
			.aad_len = 10,
			.nonce = {0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x02, 0x00, 0x00, 0x00, 0x05},
			.plaintext = {0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			.plaintext_len = 1,
			.expected_U = 0xDD2443CA,
			.expected_cipher = {0x83},
		},
		{
			.key = key2,
			.aad = {0x8c, 0x98, 0x0b, 0xb5, 0x01, 0xe2, 0x2b, 0x04, 0x00, 0x00},
			.aad_len = 10,
			//.nonce computed below
			.plaintext = {0xfe, 0x00},
			.plaintext_len = 2,
			.expected_U = 0x0a8a1d8f,
			.expected_cipher = {0xb1, 0x99},
		},
		{
			.key = key3,
			.aad = {0x8c, 0x98, 0x6b, 0x13, 0x02, 0xe2, 0xbf, 0x2b, 0x00, 0x00},
			.aad_len = 10,
			//.nonce computed below
			.plaintext = {0xfe, 0x00},
			.plaintext_len = 2,
			.expected_U = 0xd5c5f6f0,
			.expected_cipher = {0x68, 0x23},
		},
	};

	// Vec 2
	zgp_compute_nonce(0xe201b50b, 1067, false, vectors[2].nonce);
	// Vec 3
	zgp_compute_nonce(0xe202136b, 11199, false, vectors[3].nonce);

	uint8_t cipher[16];
	uint8_t U[4];
	int res = 0;

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		printf("AES-CCM encrypt - Test vector %zu\n", i);
		struct ccm_test_vector *tv = &vectors[i];

		int r = aes_ccm_ae(tv->key, 16, tv->nonce, 4,
		                   tv->plaintext, tv->plaintext_len,
		                   tv->aad, tv->aad_len,
		                   cipher, U);
		if (r != 0) {
			printf("Error: aes_ccm_ae %zu failed\n", i);
			res++;
			continue;
		}

		if (AES_GET_LE32(U) != tv->expected_U) {
			printf("Error: aes_ccm %zu: expected U = 0x%04x, got 0x%04x\n",
			    i, tv->expected_U, AES_GET_LE32(U));
			res++;
		}
		if (tv->plaintext_len > 0) {
			if (memcmp(tv->expected_cipher, cipher, tv->plaintext_len) != 0) {
				printf("Error: aes_ccm %zu: encrypted data don't match\n", i);
				res++;
			}
		}
	}

	return res;
}

static int test_aes_ccm_decrypt(void)
{
	uint8_t key[16] = {
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
		0xC8, 0xC9, 0xCa, 0xCb, 0xCc, 0xCd, 0xCe, 0xCf,
	};

	struct ccm_test_vector {
		uint8_t aad[32]; // AddAuthData
		uint8_t aad_len;
		uint8_t nonce[13];
		uint8_t cipher[16];
		uint8_t cipher_len;
		uint8_t auth[4];
		uint8_t expected_plain[16];
	} vectors[] = {
		{ /* ZigBee Green Power TX frame with SecurityLevel = 0x2 (A.1.5.6.3.1) */
			.aad = {0x8c, 0x70, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44, 0x20},
			.aad_len = 11,
			.nonce = {0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44, 0x05},
			.cipher = {0},
			.cipher_len = 0,
			.auth = {0x6e, 0xa9, 0x51, 0xbc},
		},
		{ /* ZigBee Green Power TX frame with SecurityLevel = 0x3 (A.1.5.6.3.2) */
			.aad = {0x8c, 0x78, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44},
			.aad_len = 10,
			.nonce = {0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x11, 0x22, 0x33, 0x44, 0x05},
			.cipher = {0x2A},
			.cipher_len = 1,
			.auth = {0xd9, 0xf0, 0x08, 0x6d},
			.expected_plain = {0x20},
		},
	};

	uint8_t plain[16];
	int res = 0;

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		printf("AES-CCM decrypt - Test vector %zu\n", i);
		struct ccm_test_vector *tv = &vectors[i];

		int r = aes_ccm_ad(key, sizeof(key), tv->nonce, 4,
		                   tv->cipher, tv->cipher_len,
		                   tv->aad, tv->aad_len,
		                   tv->auth, plain);
		if (r != 0) {
			printf("Error: aes_ccm_ad %zu failed\n", i);
			res++;
			continue;
		}

		if (tv->cipher_len > 0) {
			if (memcmp(tv->expected_plain, plain, tv->cipher_len) != 0) {
				printf("Error: aes_ccm %zu: decrypted data don't match\n", i);
				res++;
			}
		}
	}

	return res;
}

int main(void)
{
	int ret = 0;

	printf("Running crypto tests...\n");
	if (test_cbc() ||
	    test_ecb() ||
	    test_key_wrap() ||
	    test_aes_ctr() ||
	    test_aes_ccm_encrypt() ||
	    test_aes_ccm_decrypt())
		ret = -1;

	return ret;
}
