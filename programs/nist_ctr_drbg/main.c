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
#include <stdlib.h>

#include "nist_ctr_drbg.h"

void
do_buffer(NIST_CTR_DRBG* drbg, char* buffer, int length)
{
	nist_ctr_drbg_generate(drbg, buffer, length, NULL, 0);

	printf("%d:\n", length);
	nist_dump_hex(buffer, length);
	printf("\n");
}

int
main(int argc, char* argv[])
{
	int i;
	NIST_CTR_DRBG drbg;
	char buffer[256];

	nist_ctr_initialize();

	nist_ctr_drbg_instantiate(&drbg, "a", 1, "b", 1, "c", 1);

	do_buffer(&drbg, buffer, 1);

	do_buffer(&drbg, buffer, 15);

	do_buffer(&drbg, buffer, 16);

	do_buffer(&drbg, buffer, 17);

	do_buffer(&drbg, buffer, sizeof(buffer));

	nist_ctr_drbg_reseed(&drbg, "d", 1, "e", 1);

	do_buffer(&drbg, buffer, 17);

	nist_dump_ctr_drbg(&drbg);

	for (i = 0; i < 10000; ++i)
		nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	do_buffer(&drbg, buffer, 16);

	nist_dump_ctr_drbg(&drbg);

	return 0;
}
