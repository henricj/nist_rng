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


void ecb_vt(int keysize)
{
	int i;
	NIST_AES_ENCRYPT_CTX ctx;
	unsigned char key[NIST_AES_MAXKEYBYTES];
	unsigned char pt[NIST_AES_BLOCKSIZEBYTES];
	unsigned char ct[NIST_AES_BLOCKSIZEBYTES];

	memset(key, 0, keysize / 8);

	printf("\n==========\n\n");
	printf("KEYSIZE=%d\n", keysize);

	printf("\nKEY=");
	nist_dump_simple_hex(key, keysize / 8);
	printf("\n");

	NIST_AES_Schedule_Encryption(&ctx, &key[0], keysize);

	for (i = 1; i <= NIST_AES_BLOCKSIZEBITS; ++i) {
		printf("\nI=%d", i);

		memset(pt, 0, NIST_AES_BLOCKSIZEBYTES);
		pt[(i - 1) / 8] = 0x80U >> ((i - 1) & 0x07);

		printf("\nPT=");
		nist_dump_simple_hex(pt, NIST_AES_BLOCKSIZEBYTES);

		NIST_AES_ECB_Encrypt(&ctx, pt, ct);

		printf("\nCT=");
		nist_dump_simple_hex(ct, NIST_AES_BLOCKSIZEBYTES);
		printf("\n");
	}
}

int
main(int argc, char* argv[])
{
	ecb_vt(128);
	ecb_vt(192);
	ecb_vt(256);

	printf("\n==========");

	return 0;
}

