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

#ifndef C7RANDOM_H
#define C7RANDOM_H

#if defined(__GNUC__)
static __inline int
padlock_xstore_rng(void* buffer)
{
	int rv;

	__asm __volatile("xstore-rng"
		: "=a" (rv), "+D" (buffer)
		: "d" (0)
		: "memory" );

	return rv;
}
#elif defined(_MSC_VER)
__inline int
padlock_xstore_rng(void* buffer)
{
	int rv;
	int rate = 0;

	_asm
	{
		mov edx, rate
		mov edi, buffer

		_emit 0x0f
		_emit 0xa7
		_emit 0xc0

		mov rv, eax
	}

	return rv;
}
#else
#error "Implement me"
#endif

extern long long size;
void nist_rbg(void);

#endif /* C7RANDOM_H */

