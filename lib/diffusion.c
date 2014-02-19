/*
 * Copyright (c) 2007 Henric Jungheim <software@henric.info>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * NIST SP 800-90 CTR_DRBG (Random Number Generator)
 */

#include "nist_ctr_drbg.h"

#include <stdio.h>
#include <string.h>

int count;

static void
nist_ctr_drbg_diffusion_32(const NIST_Key* ctx, unsigned int* data)
{
	int i, j;
	unsigned int buffer[NIST_BLOCK_OUTLEN_INTS];

	for (i = 0; i < NIST_BLOCK_OUTLEN_INTS; ++i) {
		for (j = i + 1; j < NIST_BLOCK_OUTLEN_INTS; ++j) {
			/* Swap data[i * 4 + j] and data[j * 4 + i] */
			unsigned int x = data[i * 4 + j];
			data[i * 4 + j] = data[j * 4 + i];
			data[j * 4 + i] = x;
		}
	}

	for (i = 0; i < 4; ++i) {
		Block_Encrypt(ctx, &data[i * 4], buffer);
		++count;
		memcpy(&data[i * 4], buffer, NIST_BLOCK_OUTLEN_BYTES);
	}
}

static void
nist_ctr_drbg_diffusion_32_array(const NIST_Key* ctx, unsigned int* data[])
{
	int i, j;
	unsigned int buffer[NIST_BLOCK_OUTLEN_INTS];

	for (i = 0; i < 4; ++i) {
		for (j = i + 1; j < 4; ++j) {
			unsigned int x = data[i][j];
			data[i][j] = data[j][i];
			data[j][i] = x;
		}
	}

	for (i = 0; i < 4; ++i) {
		Block_Encrypt(ctx, &data[i][0], buffer);
		++count;
		memcpy(&data[i][0], buffer, NIST_BLOCK_OUTLEN_BYTES);
	}
}

static void
nist_ctr_drbg_diffusion_quad_32(const NIST_Key* ctx, unsigned int* data[])
{
	int i, j;

	for (i = 0; i < 4; ++i) {
		for (j = i + 1; j < 4; ++j) {
			unsigned int* x = data[i * 4 + j];
			data[i * 4 + j] = data[j * 4 + i];
			data[j * 4 + i] = x;
		}
	}

	for (i = 0; i < 4; ++i) {
		nist_ctr_drbg_diffusion_32_array(ctx, &data[i * 4]);
		nist_ctr_drbg_diffusion_32_array(ctx, &data[i * 4]);
	}
}

static void
nist_ctr_drbg_diffusion_8_array(const NIST_Key* ctx, unsigned char* data[])
{
	int i, j;
	unsigned int buffer[NIST_BLOCK_OUTLEN_BYTES];

	for (i = 0; i < 16; ++i) {
		for (j = i + 1; j < 16; ++j) {
			unsigned char x = data[i][j];
			data[i][j] = data[j][i];
			data[j][i] = x;
		}
	}

	for (i = 0; i < 16; ++i) {
		Block_Encrypt(ctx, &data[i][0], buffer);
		++count;
		memcpy(&data[i][0], buffer, NIST_BLOCK_OUTLEN_BYTES);
	}
}

static void
nist_ctr_drbg_diffusion_quad_8(const NIST_Key* ctx, unsigned char* data[])
{
	int i, j;

	for (i = 0; i < 16; ++i) {
		for (j = i + 1; j < 16; ++j) {
			unsigned char* x = data[i * 16 + j];
			data[i * 16 + j] = data[j * 16 + i];
			data[j * 16 + i] = x;
		}
	}

	for (i = 0; i < 16; ++i) {
		nist_ctr_drbg_diffusion_8_array(ctx, &data[i * 16]);
		nist_ctr_drbg_diffusion_8_array(ctx, &data[i * 16]);
	}
}

void checkme(NIST_CTR_DRBG* drbg)
{
	int i, j, k;
	unsigned char* buffer[16 * 16];
	unsigned char backing[16 * 16 * NIST_BLOCK_OUTLEN_BYTES];

	for (k = 0; k < 2; ++k) {
	for (i = 0; i < 16 * 16; ++i) {
		buffer[i] = &backing[NIST_BLOCK_OUTLEN_BYTES * i];
		for (j = 0; j < NIST_BLOCK_OUTLEN_BYTES; ++j) {
			buffer[i][j] = 0; //(i << 16) | j;
		}
	}
	buffer[0][0] = (unsigned char)k;

	printf("***********************************************\n");
	printf("Initial value (%d):\n", k);
	for (i = 0; i < 16 * 16; ++i) {
		printf("% 4d:", i);
		for (j = 0; j < 16; ++j) {
			printf("%02x", buffer[i][j]);
		}
		printf("\n");
	}
	nist_ctr_drbg_diffusion_quad_8(&drbg->ctx, buffer);
	printf("After pass 1:\n");
	for (i = 0; i < 16 * 16; ++i) {
		printf("% 4d:", i);
		for (j = 0; j < 16; ++j) {
			printf("%02x", buffer[i][j]);
		}
		printf("\n");
	}
	nist_ctr_drbg_diffusion_quad_8(&drbg->ctx, buffer);

	printf("After pass 2:\n");
	for (i = 0; i < 16 * 16; ++i) {
		printf("% 4d:", i);
		for (j = 0; j < 16; ++j) {
			printf("%02x", buffer[i][j]);
		}
		printf("\n");
	}
	}
}
