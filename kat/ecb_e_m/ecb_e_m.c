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

#include <stdio.h>
#include <string.h>

#include "nist_ctr_drbg.h"


void ecb_e_m(int keysize)
{
	int i, j;
	NIST_AES_ENCRYPT_CTX ctx;
	unsigned char key[NIST_AES_MAXKEYBYTES];
	unsigned char pt[NIST_AES_BLOCKSIZEBYTES];
	unsigned char ct[2][NIST_AES_BLOCKSIZEBYTES];

	memset(key, 0, keysize / 8);
	memset(pt, 0, NIST_AES_BLOCKSIZEBYTES);

	printf("\n=========================\n\n");
	printf("KEYSIZE=%d\n", keysize);


	for (i = 0; i <= 399; ++i) {
		printf("\nI=%d", i);

		printf("\nKEY=");
		nist_dump_simple_hex(key, keysize / 8);

		printf("\nPT=");
		nist_dump_simple_hex(pt, NIST_AES_BLOCKSIZEBYTES);

		NIST_AES_Schedule_Encryption(&ctx, &key[0], keysize);

		for (j = 0; j <= 9999; ++j) {
			NIST_AES_ECB_Encrypt(&ctx, &pt[0], &ct[j & 1][0]);
			memcpy(&pt[0], &ct[j & 1][0], NIST_AES_BLOCKSIZEBYTES);
		}

		printf("\nCT=");
		nist_dump_simple_hex(&ct[1][0], NIST_AES_BLOCKSIZEBYTES);
		printf("\n");

		for (j = 0; j < keysize / 8; ++j) {
			int ctIndex = (NIST_AES_MAXKEYBYTES - keysize / 8) + j;
			int ctN = ctIndex >= NIST_AES_BLOCKSIZEBYTES ? 1 : 0;

			key[j] ^= ct[ctN][ctIndex & (NIST_AES_BLOCKSIZEBYTES - 1)];
		}
	}
}

int
main(int argc, char* argv[])
{
	ecb_e_m(128);
	ecb_e_m(192);
	ecb_e_m(256);

	printf("\n===========");

	return 0;
}

