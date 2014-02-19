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

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "nist_ctr_drbg.h"

#ifdef NIST_AES_PADLOCK_H

#define PADLOCK_ACE_CW_ROUND_MASK       0x0fU
#define PADLOCK_ACE_CW_KEYGN            (1U << 7)
#define PADLOCK_ACE_CW_KEYSZ_128        (0U << 10)
#define PADLOCK_ACE_CW_KEYSZ_192        (1U << 10)
#define PADLOCK_ACE_CW_KEYSZ_256        (2U << 10)

#if defined(__GNUC__)
static __inline void
padlock_new_key()
{
        __asm __volatile("pushfl; popfl" : : : "cc");
}

static __inline void
padlock_aes_ecb(const void* src, void* dst, int count, const unsigned int* ace_cw, const void* key)
{
        __asm __volatile("rep xcrypt-ecb"
                : "+S" (src), "+D" (dst)
                : "c" (count), "d" (ace_cw), "b" (key)
                : "memory", "cc");
}
#elif defined(_MSC_VER)
static __inline void
padlock_new_key()
{
	_asm
	{
		pushfd
		popfd
	}
}

static __inline void
padlock_aes_ecb(const void* src, void* dst, int count, const unsigned int* ace_cw, const void* key)
{
	_asm
	{
		mov edx, ace_cw
		mov ebx, key
		mov ecx, count
		mov edi, dst
		mov esi, src
		_emit 0xf3
		_emit 0x0f
		_emit 0x0a7
		_emit 0xc8
	}
}

#else
#error "Implement me"
#endif

static const NIST_AES_ENCRYPT_CTX* padlock_last_ctx;

static __inline void*
align(void* p, int n)
{
	int i;

	/*
	 * It would be great if "intptr_t" could be found in
	 * some standard place.
	 */
	ptrdiff_t pd = (const char *)p - (const char *)0;

	i = (int)(pd & (n - 1));

	if (!i)
		return p;

	return n - i + (char *)p;
}

static __inline int
check_align(const void* p, int n)
{
	/*
	 * It would be great if "intptr_t" could be found in
	 * some standard place.
	 */
	ptrdiff_t pd = (const char *)p - (const char *)0;

	return !(pd & (n - 1));
}

void
NIST_AES_ECB_Encrypt(const NIST_AES_ENCRYPT_CTX* ctx, const void* src, void* dst)
{
	const void* s = src;
	void* d = dst;

	if (padlock_last_ctx != ctx) {
		padlock_new_key(); 
		padlock_last_ctx = ctx;
	}

	if (!check_align(src, 16)) {
		memcpy(ctx->input, src, NIST_BLOCK_OUTLEN_BYTES);
		s = ctx->input;
	}

	if (!check_align(dst, 16))
		d = ctx->output;

	padlock_aes_ecb(s, d, 1, &ctx->ace_cw[0], &ctx->ek[0]);

	if (d != dst)
		memcpy(dst, d, NIST_BLOCK_OUTLEN_BYTES);
}

int
NIST_AES_Schedule_Encryption(NIST_AES_ENCRYPT_CTX* ctx, const void* key, int bits)
{
	int i;
	int genKey = 0;
	
	ctx->ace_cw = align(&ctx->buffer[0], 16);
	ctx->input = &ctx->ace_cw[4];
	ctx->output = &ctx->input[4];
	ctx->ek = &ctx->output[4];

	memset(&ctx->ace_cw[0], 0, sizeof(ctx->ace_cw));

	switch (bits) {
	case 256:
 		ctx->ace_cw[0] = PADLOCK_ACE_CW_KEYGN | PADLOCK_ACE_CW_KEYSZ_256;
		genKey = 1;
		break;
	case 192:
 		ctx->ace_cw[0] = PADLOCK_ACE_CW_KEYGN | PADLOCK_ACE_CW_KEYSZ_192;
		genKey = 1;
		break;
	case 128:
 		ctx->ace_cw[0] = PADLOCK_ACE_CW_KEYSZ_128;
		break;
	default:
		return 1;
	}

	if (genKey) {
		ctx->Nr = rijndaelKeySetupEnc(&ctx->ek[0], (const unsigned char *)key, bits);
		if (!ctx->Nr)
			return 1;

		for (i = 0; i < 4 * (AES_MAXROUNDS + 1); ++i)
			ctx->ek[i] = NIST_HTONL(ctx->ek[i]);
	} else {
		ctx->Nr = 10;
		memcpy(&ctx->ek[0], key, 128 / 8);
	}

	ctx->ace_cw[0] |= ctx->Nr;

	if (padlock_last_ctx == ctx)
		padlock_new_key();

	return 0;
}

#endif /* NIST_AES_PADLOCK_H */

