/*
 * Copyright (c) 2007,2016 Henric Jungheim <software@henric.info>
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
#include <memory.h>

#include "nist_ctr_drbg.h"

void
do_buffer(NIST_CTR_DRBG* drbg, char* buffer, int length)
{
	nist_ctr_drbg_generate(drbg, buffer, length, NULL, 0);

	printf("%d:\n", length);
	nist_dump_hex(buffer, length);
	printf("\n");
}

/*
 * The check_tv*() functions use some of the test vectors from:
 *    http://csrc.nist.gov/groups/STM/cavp/random-number-generation.html#test-vectors
 *
 */

void check_tv1()
{
	printf("tv1\n");

	/*
	[AES-256 use df]
	[PredictionResistance = False]
	[EntropyInputLen = 256]
	[NonceLen = 128]
	[PersonalizationStringLen = 0]
	[AdditionalInputLen = 0]
	[ReturnedBitsLen = 512]

	COUNT = 0
	EntropyInput = 36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14
	Nonce = 496f25b0f1301b4f501be30380a137eb
	PersonalizationString =
	** INSTANTIATE:
	Key = 3363d9000e6db47c16d3fc65f2872c08a35f99b2d174afa537a66ec153052d98
	V   = 9ee8d2e9c618ccbb8e66b5eb5333dce1

	AdditionalInput =
	** GENERATE (FIRST CALL):
	Key = b1dff09c816af6d4b2111fe63c4507cb196154f8c59957a94a2b641a7c16cc01
	V   = 69eec01b2dd4ff3aab5fac9467f54485

	AdditionalInput =
	ReturnedBits = 5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d
	** GENERATE (SECOND CALL):
	Key = 33a1f160b0bde1dd55fc314c3d1620c0581ace8b32f062fb1ed54cdecdc17694
	V   = f537c07f36573a26b3f55c8b9f7246d1
	*/
	const char EntropyInput[] = { 0x36, 0x40, 0x19, 0x40, 0xfa, 0x8b, 0x1f, 0xba, 0x91, 0xa1, 0x66, 0x1f, 0x21, 0x1d, 0x78, 0xa0, 0xb9, 0x38, 0x9a, 0x74, 0xe5, 0xbc, 0xcf, 0xec, 0xe8, 0xd7, 0x66, 0xaf, 0x1a, 0x6d, 0x3b, 0x14 };
	const char Nonce[] = { 0x49, 0x6f, 0x25, 0xb0, 0xf1, 0x30, 0x1b, 0x4f, 0x50, 0x1b, 0xe3, 0x03, 0x80, 0xa1, 0x37, 0xeb };
	const char ReturnedBits[] = { 0x58, 0x62, 0xeb, 0x38, 0xbd, 0x55, 0x8d, 0xd9, 0x78, 0xa6, 0x96, 0xe6, 0xdf, 0x16, 0x47, 0x82, 0xdd, 0xd8, 0x87, 0xe7, 0xe9, 0xa6, 0xc9, 0xf3, 0xf1, 0xfb, 0xaf, 0xb7, 0x89, 0x41, 0xb5, 0x35, 0xa6, 0x49, 0x12, 0xdf, 0xd2, 0x24, 0xc6, 0xdc, 0x74, 0x54, 0xe5, 0x25, 0x0b, 0x3d, 0x97, 0x16, 0x5e, 0x16, 0x26, 0x0c, 0x2f, 0xaf, 0x1c, 0xc7, 0x73, 0x5c, 0xb7, 0x5f, 0xb4, 0xf0, 0x7e, 0x1d };

	NIST_CTR_DRBG drbg;
	char buffer[sizeof(ReturnedBits)];

	nist_ctr_drbg_instantiate(&drbg, EntropyInput, sizeof(EntropyInput), Nonce, sizeof(Nonce), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_destroy(&drbg);

	nist_dump_hex(buffer, sizeof(buffer));

	printf(0 == memcmp(ReturnedBits, buffer, sizeof(buffer)) ? "\nValidated\n" : "\nFailed validation\n");
}

void check_tv2()
{
	printf("tv2\n");

	/*
	[AES-256 use df]
	[PredictionResistance = False]
	[EntropyInputLen = 256]
	[NonceLen = 128]
	[PersonalizationStringLen = 0]
	[AdditionalInputLen = 256]
	[ReturnedBitsLen = 512]

	COUNT = 0
	EntropyInput = 8148d65d86513ce7d38923ec2f26b9e7c677dcc8997e325b7372619e753ed944
	Nonce = 41c71a24d17d974190982bb7515ce7f5
	PersonalizationString =
	** INSTANTIATE:
	Key = fe96784a3968b04aca2079e4bc1b7674e59d0bcb9d1168fb26cacd830ffde509
	V   = 24274380ee9aa72b730efae01987a16e

	AdditionalInput = 55b446046c2d14bdd0cdba4b71873fd4762650695a11507949462da8d964ab6a
	** GENERATE (FIRST CALL):
	Key = ec013aa81ec90251e399774516481a22736bd89b5a5a6a7198da7cfceb741c59
	V   = 9e34cdda08a3c193231647953c73a8db

	AdditionalInput = 91468f1a097d99ee339462ca916cb4a10f63d53850a4f17f598eac490299b02e
	ReturnedBits = 54603d1a506132bbfa05b153a04f22a1d516cc46323cef15111af221f030f38d6841d4670518b4914a4631af682e7421dffaac986a38e94d92bfa758e2eb101f
	** GENERATE (SECOND CALL):
	Key = c13f343817bf7fcaafc49023e633f3222a16f3ae3c608880aa8e7e0f6b67b05a
	V   = a644cb76114072fa7fdd5715746ee41a
	*/
	const char EntropyInput[] = { 0x81, 0x48, 0xd6, 0x5d, 0x86, 0x51, 0x3c, 0xe7, 0xd3, 0x89, 0x23, 0xec, 0x2f, 0x26, 0xb9, 0xe7, 0xc6, 0x77, 0xdc, 0xc8, 0x99, 0x7e, 0x32, 0x5b, 0x73, 0x72, 0x61, 0x9e, 0x75, 0x3e, 0xd9, 0x44 };
	const char Nonce[] = { 0x41, 0xc7, 0x1a, 0x24, 0xd1, 0x7d, 0x97, 0x41, 0x90, 0x98, 0x2b, 0xb7, 0x51, 0x5c, 0xe7, 0xf5 };
	const char AdditionalInput1[] = { 0x55, 0xb4, 0x46, 0x04, 0x6c, 0x2d, 0x14, 0xbd, 0xd0, 0xcd, 0xba, 0x4b, 0x71, 0x87, 0x3f, 0xd4, 0x76, 0x26, 0x50, 0x69, 0x5a, 0x11, 0x50, 0x79, 0x49, 0x46, 0x2d, 0xa8, 0xd9, 0x64, 0xab, 0x6a };
	const char AdditionalInput2[] = { 0x91, 0x46, 0x8f, 0x1a, 0x09, 0x7d, 0x99, 0xee, 0x33, 0x94, 0x62, 0xca, 0x91, 0x6c, 0xb4, 0xa1, 0x0f, 0x63, 0xd5, 0x38, 0x50, 0xa4, 0xf1, 0x7f, 0x59, 0x8e, 0xac, 0x49, 0x02, 0x99, 0xb0, 0x2e };
	const char ReturnedBits[] = { 0x54, 0x60, 0x3d, 0x1a, 0x50, 0x61, 0x32, 0xbb, 0xfa, 0x05, 0xb1, 0x53, 0xa0, 0x4f, 0x22, 0xa1, 0xd5, 0x16, 0xcc, 0x46, 0x32, 0x3c, 0xef, 0x15, 0x11, 0x1a, 0xf2, 0x21, 0xf0, 0x30, 0xf3, 0x8d, 0x68, 0x41, 0xd4, 0x67, 0x05, 0x18, 0xb4, 0x91, 0x4a, 0x46, 0x31, 0xaf, 0x68, 0x2e, 0x74, 0x21, 0xdf, 0xfa, 0xac, 0x98, 0x6a, 0x38, 0xe9, 0x4d, 0x92, 0xbf, 0xa7, 0x58, 0xe2, 0xeb, 0x10, 0x1f };

	NIST_CTR_DRBG drbg;
	char buffer[sizeof(ReturnedBits)];

	nist_ctr_drbg_instantiate(&drbg, EntropyInput, sizeof(EntropyInput), Nonce, sizeof(Nonce), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), AdditionalInput1, sizeof(AdditionalInput1));

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), AdditionalInput2, sizeof(AdditionalInput2));

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_destroy(&drbg);

	nist_dump_hex(buffer, sizeof(buffer));

	printf(0 == memcmp(ReturnedBits, buffer, sizeof(buffer)) ? "\nValidated\n" : "\nFailed validation\n");
}

void check_tv3()
{
	printf("tv3\n");
	/*
	[AES-256 use df]
	[PredictionResistance = True]
	[EntropyInputLen = 256]
	[NonceLen = 128]
	[PersonalizationStringLen = 0]
	[AdditionalInputLen = 0]

	COUNT = 0
	EntropyInput = c18081a65d44021619b3f180b1c920026a546f0c7081498b6ea662526d51b1cb
	Nonce = d254fcff021e69d229c9cfad85fa486c
	PersonalizationString =
	AdditionalInput =
	EntropyInputPR = 583bfad5375ffbc9ff46d219c7223e95459d82e1e7229f633169d26b57474fa3
	INTERMEDIATE Key = 251803593aec72cc90b6287497b9965fa7d77bf85cc741262e376fd541d6c379
	INTERMEDIATE V = bdf3545b98814d840f922be8b395d211
	INTERMEDIATE ReturnedBits = aacecd2d8fb228b8f8f9c4152e96bc13
	AdditionalInput =
	EntropyInputPR = 37c9981c0bfb91314d55b9e91c5a5ee49392cfc52312d5562c4a6effdc10d068
	ReturnedBits = 34011656b429008f3563ecb5f2590723
	*/
	const char EntropyInput[] = { 0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16, 0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02, 0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b, 0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb };
	const char Nonce[] = { 0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2, 0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c };
	const char PR[] = { 0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9, 0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95, 0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63, 0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3 };
	const char PR2[] = { 0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31, 0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4, 0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56, 0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 };
	const char ReturnedBits[] = { 0x34, 0x01, 0x16, 0x56, 0xb4, 0x29, 0x00, 0x8f, 0x35, 0x63, 0xec, 0xb5, 0xf2, 0x59, 0x07, 0x23 };

	NIST_CTR_DRBG drbg;
	char buffer[sizeof(ReturnedBits)];

	nist_ctr_drbg_instantiate(&drbg, EntropyInput, sizeof(EntropyInput), Nonce, sizeof(Nonce), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_reseed(&drbg, PR, sizeof(PR), NULL, 0);
	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_reseed(&drbg, PR2, sizeof(PR2), NULL, 0);
	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_destroy(&drbg);

	nist_dump_hex(buffer, sizeof(buffer));

	printf(0 == memcmp(ReturnedBits, buffer, sizeof(buffer)) ? "\nValidated\n" : "\nFailed validation\n");
}

void check_tv4()
{
	printf("tv4\n");

	/*
	[AES-256 use df]
	[PredictionResistance = False]
	[EntropyInputLen = 256]
	[NonceLen = 128]
	[PersonalizationStringLen = 0]
	[AdditionalInputLen = 0]

	COUNT = 0
	EntropyInput = 5a194d5e2b31581454def675fb7958fec7db873e5689fc9d03217c68d8033820
	Nonce = 1b54b8ff0642bff521f15c1c0b665f3f
	PersonalizationString =
	AdditionalInput =
	INTERMEDIATE Key = b839fa3b11b77ac80f101e14afa7f85211048d745d8eaaa4bda9dca2a56259c1
	INTERMEDIATE V = b0ee8dfa67ecfd5c8dca69adc0b75e8d
	INTERMEDIATE ReturnedBits = 3f6db52dff53ae68e92abcd8131ef8bf
	EntropyInputReseed = f9e65e04d856f3a9c44a4cbdc1d00846f5983d771c1b137e4e0f9d8ef409f92e
	AdditionalInputReseed =
	AdditionalInput =
	ReturnedBits = a054303d8a7ea9889d903e077c6f218f
	*/
	const char EntropyInput[] = { 0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58, 0x14, 0x54, 0xde, 0xf6, 0x75, 0xfb, 0x79, 0x58, 0xfe, 0xc7, 0xdb, 0x87, 0x3e, 0x56, 0x89, 0xfc, 0x9d, 0x03, 0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38, 0x20 };
	const char Nonce[] = { 0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf, 0xf5, 0x21, 0xf1, 0x5c, 0x1c, 0x0b, 0x66, 0x5f, 0x3f };
	const char ReseedEntropy[] = { 0xf9, 0xe6, 0x5e, 0x04, 0xd8, 0x56, 0xf3, 0xa9, 0xc4, 0x4a, 0x4c, 0xbd, 0xc1, 0xd0, 0x08, 0x46, 0xf5, 0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13, 0x7e, 0x4e, 0x0f, 0x9d, 0x8e, 0xf4, 0x09, 0xf9, 0x2e };
	const char ReturnedBits[] = { 0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9, 0x88, 0x9d, 0x90, 0x3e, 0x07, 0x7c, 0x6f, 0x21, 0x8f };

	NIST_CTR_DRBG drbg;
	char buffer[sizeof(ReturnedBits)];

	nist_ctr_drbg_instantiate(&drbg, EntropyInput, sizeof(EntropyInput), Nonce, sizeof(Nonce), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_reseed(&drbg, ReseedEntropy, sizeof(ReseedEntropy), NULL, 0);

	nist_ctr_drbg_generate(&drbg, buffer, sizeof(buffer), NULL, 0);

	nist_dump_ctr_drbg(&drbg);

	nist_ctr_drbg_destroy(&drbg);

	nist_dump_hex(buffer, sizeof(buffer));

	printf(0 == memcmp(ReturnedBits, buffer, sizeof(buffer)) ? "\nValidated\n" : "\nFailed validation\n");
}

void check_tv()
{
	check_tv1();
	check_tv2();
	check_tv3();
	check_tv4();
}

int
main(int argc, char* argv[])
{
	int i;
	NIST_CTR_DRBG drbg;
	char buffer[256];

	nist_ctr_initialize();

	check_tv();

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
