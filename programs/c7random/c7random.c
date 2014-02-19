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
#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c7random.h"

int paranoia;
int whiten;
long long size;

#define SHA_256(SIZE, DATA, HASH) asm volatile ("rep xsha256\n" \
                :  "+S" (DATA), "+D" (HASH) \
                : "c" (SIZE), "a" (0) \
                : "memory");


void
whiten8(unsigned int *target)
{
	int i;
	unsigned int rv, length, buffer[2];

	for (i = 0; i < 8; i += 2) {
		do {
			unsigned int* p = buffer;

			__asm __volatile("xstore-rng"
			    : "=a" (rv), "+D" (p)
			    : "d" (0)
			    : "memory" );
			length = rv & 0xf;
		} while (!length);

		if (8 != length) {
			fprintf(stderr, "Invalid length (%d)\n", length);
			exit(2);
		}

		target[i] ^= buffer[0];
		target[i + 1] ^= buffer[1];
	}
}

void
generate()
{
	int i, j;
	size_t len, left;
	unsigned int rv, length;
	unsigned int buffer[14];	/* 448 bits */
        unsigned int hash[(128 + 16) / 4] __attribute__ ((aligned (16)));
	unsigned int *pb0 = buffer, *ph0 = hash;
	unsigned int *pb, *ph;

        hash[0] = 0x6a09e667;
        hash[1] = 0xbb67ae85;
        hash[2] = 0x3c6ef372;
        hash[3] = 0xa54ff53a;
        hash[4] = 0x510e527f;
        hash[5] = 0x9b05688c;
        hash[6] = 0x1f83d9ab;
        hash[7] = 0x5be0cd19;
	
        for (;;) {
		for (i = 0; i <= paranoia; ++i) {
			for (j = 0; j < sizeof(buffer) / sizeof(buffer[0]); j += 2) {
				do {
					unsigned int* p = pb0 + j;

					__asm __volatile("xstore-rng"
					    : "=a" (rv), "+D" (p)
			                    : "d" (0)
			                    : "memory" );

					length = rv & 0xf;
				} while (!length);

				if (8 != length) {
					fprintf(stderr, "Invalid length (%d)\n", length);
					exit(2);
				}
			}

			pb = pb0;
			ph = ph0;

        		SHA_256(sizeof buffer - 1, pb, ph);

			if (paranoia)
				whiten8(hash);
		}

		
		left = !size || size > 32 ? 32 : size;
		len = fwrite(hash, 1, left, stdout);
		if (left != len)
			exit(1);

		if (whiten)
			whiten8(hash);

		if (size) {
			size -= left;
			if (size <= 0)
				break;
		}
        }
}


void
generate_xor()
{
	int i;
	size_t len, left;
	unsigned int rnd[8];

        for (;;) {
		for (i = 0; i <= paranoia; ++i)
			whiten8(rnd);

		left = !size || size > 32 ? 32 : size;
		len = fwrite(rnd, 1, left, stdout);
		if (left != len)
			exit(1);

		if (whiten)
			whiten8(rnd);

		if (size) {
			size -= left;
			if (size <= 0)
				break;
		}
        }
}

int
main(int argc, char *argv[])
{
	int c;
	const char* errstr;
	int xor = 0, nist = 0;

	while (-1 != (c = getopt(argc, argv, "Nxws:p:"))) {
		switch (c) {
		case 'x':
			xor = 1;
			break;
		case 'w':
			whiten = 1;
			break;
		case 's':
			size = strtonum(optarg, 1, LLONG_MAX, &errstr);
	
			if (errstr)
				errx(1, "size %s: %s", errstr, optarg);

			break;
			
		case 'p':
			paranoia = (int)strtonum(optarg, 1, 50000, &errstr);
	
			if (errstr)
				errx(1, "paranoia %s: %s", errstr, optarg);

			break;
		case 'N':
			nist = 1;
		default:
			// usage();
			break;
		}
	}

	if (nist)
		nist_rbg();
	else if (xor)
		generate_xor();
	else
		generate();

	fclose(stdout);

	return 0;
}

