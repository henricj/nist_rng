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
 * Interface adapter for Rijndael implmentation (for use by NIST SP 800-90 CTR_DRBG)
 */

#ifndef NIST_AES_PADLOCK_H
#define NIST_AES_PADLOCK_H

#ifdef _MSC_VER
#include <stdlib.h>
#endif

/* We still need the software implementation for >128 bit key scheduling */
#ifndef __RIJNDAEL_H
#include "rijndael.h"
#endif

#define NIST_AES_MAXKEYBITS		256
#define NIST_AES_MAXKEYBYTES	(NIST_AES_MAXKEYBITS / 8)
#define NIST_AES_MAXKEYINTS	(NIST_AES_MAXKEYBYTES / sizeof(int))

#define NIST_AES_BLOCKSIZEBITS	128
#define NIST_AES_BLOCKSIZEBYTES	(NIST_AES_BLOCKSIZEBITS / 8)
#define NIST_AES_BLOCKSIZEINTS	(NIST_AES_BLOCKSIZEBYTES / sizeof(int))

typedef struct {
	int Nr;			/* key-length-dependent number of rounds */
	unsigned int* ace_cw;	/* ACE padlock control word */
	unsigned int* input;	/* aligned input buffer */
	unsigned int* output;	/* aligned output buffer */
	unsigned int* ek;	/* encrypt key schedule */

	/*
	 * Use a buffer large enough to 16-byte alignment for both
	 * ace_cw and ek.
	 */
	unsigned int buffer [3 + 4 * 3 + 4*(AES_MAXROUNDS + 1)];
} NIST_AES_ENCRYPT_CTX;

static __inline unsigned int
padlock_bswap(unsigned int n)
{
#if defined(__GNUC__)
	asm("bswapl %0" : "+r" (n) : : "cc");
	return n;
#elif defined(_MSC_VER)
	return _byteswap_ulong(n);
#else
#error "Do something..."
#endif
}

#define NIST_HTONL(x) padlock_bswap(x)

int
NIST_AES_Schedule_Encryption(NIST_AES_ENCRYPT_CTX* ctx, const void* key, int bits);

void
NIST_AES_ECB_Encrypt(const NIST_AES_ENCRYPT_CTX* ctx, const void* src, void* dst);

#endif /* NIST_AES_PADLOCK_H */
