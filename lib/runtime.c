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

#if 0
#include <stdio.h>
#include <stdlib.h>
#include <machine/pctr.h>

#include "nist_ctr_drbg.h"

void
runtime(NIST_CTR_DRBG* drbg, char* buffer, int length)
{
	u_quad_t start, elapsed;
	u_quad_t best = ~0ULL;
	double perByte;
	const int ITERATIONS = 100000;
	int i, j;

	for (i = 0; i < 10; ++i) {
		start = rdtsc();

		for (j = 0; j < ITERATIONS; ++j) {
			nist_ctr_drbg_generate(drbg, buffer, length, NULL, 0);
			drbg->reseed_counter = 0;
		}

		elapsed = rdtsc() - start;

		if (elapsed < best)
			best = elapsed;
	}

	perByte = best * (1.0 / ITERATIONS);
	perByte /= length;

	printf("%g clocks, %g clocks/byte\n", (double)best, perByte);
}
#endif

