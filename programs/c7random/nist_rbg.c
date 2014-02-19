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

#include "nist_ctr_drbg.h"
#include "c7random.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct nonce {
	time_t init_time;
	char hostname[128];
	uid_t uid;
	pid_t pid;
	long long count;
	char kern_entropy[128];
};

static struct nonce rbg_nonce;

int
nist_rbg_generate(NIST_CTR_DRBG* drbg, void* buffer, int buffer_length,
	const void* additional_input, int additional_input_length);

static int
nist_rbg_get_entropy(void* entropy, int min_length, int buffer_length)
{
	int count = 0, rv, len;
	int buffer[2];
	char* p = (char*)entropy;

	for (;;) {
		rv = padlock_xstore_rng(buffer);
		len = rv & 0x0f;

		if (len < 1) {
			if (count >= min_length) {
				nist_zeroize(buffer, sizeof(buffer));
				return count;
			}

			continue;
		}

		if (len > buffer_length - count) {
			len = buffer_length - count;

			if (!len) {
				nist_zeroize(buffer, sizeof(buffer));
				return count;
			}
		}

		memcpy(p, buffer, len);	
		p += len;
		count += len;

		if (count >= buffer_length) {
			nist_zeroize(buffer, sizeof(buffer));
			return count;
		}
	}
}

static void
nist_rbg_update_nonce()
{
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (-1 != fd) {
		read(fd, rbg_nonce.kern_entropy, sizeof (rbg_nonce.kern_entropy));
		close(fd);
	}

	pid_t pid = getpid();

	if (rbg_nonce.count && pid == rbg_nonce.pid) {
		++rbg_nonce.count;
		if (rbg_nonce.count)
			return;

		/*
		 * Fall through to update time, so we
		 * don't repeat ourselves.
		 */
	}


	if (!rbg_nonce.count) {
		rbg_nonce.count = 1;
		rbg_nonce.init_time = time(NULL);
	}

	gethostname(rbg_nonce.hostname, sizeof(rbg_nonce.hostname));
	rbg_nonce.uid = getuid();
	rbg_nonce.pid = pid;
}

int
nist_rbg_reseed(NIST_CTR_DRBG* drbg)
{
	int ret;
	char entropy[2 * NIST_BLOCK_SEEDLEN_BYTES];

	nist_rbg_update_nonce();

	ret = nist_rbg_get_entropy(entropy, sizeof(entropy), sizeof(entropy));
	if (sizeof(entropy) != ret)
		return 1;

	ret = nist_ctr_drbg_reseed(drbg, entropy, sizeof(entropy),
		&rbg_nonce, sizeof(rbg_nonce));

	nist_zeroize(entropy, sizeof(entropy));

	return ret;
}


int
nist_rbg_instantiate(NIST_CTR_DRBG* drbg,
	const void* personalization_string, int personalization_string_length)
{
	int ret;
	int entropy_count;
	char entropy[2 * NIST_BLOCK_SEEDLEN_BYTES];

	nist_rbg_update_nonce();

	entropy_count = nist_rbg_get_entropy(entropy, NIST_BLOCK_SEEDLEN_BYTES, sizeof(entropy));

	if (entropy_count < NIST_BLOCK_SEEDLEN_BYTES)
		return 1;	

	ret = nist_ctr_drbg_instantiate(drbg,
		entropy, entropy_count,
		&rbg_nonce, sizeof(rbg_nonce),
		personalization_string, personalization_string_length);

	/*
	 * Generate some throw-away data both to stir things up a bit    
	 * and to make sure "nist_rbg_generate()" is happy before we
	 * tell our caller that their drbg is ready for use.
	 */
	if (!ret)
		ret = nist_rbg_generate(drbg, entropy, sizeof(entropy), NULL, 0);

	nist_zeroize(entropy, entropy_count);

	/* Also make sure that we can reseed. */
	if (!ret)
		ret = nist_rbg_reseed(drbg);

	return ret;
}

int
nist_rbg_generate(NIST_CTR_DRBG* drbg, void* buffer, int buffer_length,
	const void* additional_input, int additional_input_length)
{
	int length, ret;
	char *p = (char*)buffer;;
	char entropy[2 * NIST_BLOCK_OUTLEN_BYTES];

	for (p = (char*)buffer; buffer_length > 0;
			p += length, buffer_length -= length) {
		length = nist_rbg_get_entropy(entropy,
				(11 * NIST_BLOCK_OUTLEN_BYTES + 9) / 10, sizeof(entropy));

		if (length < (11 * NIST_BLOCK_OUTLEN_BYTES + 9) / 10)
			return 1;

		ret = nist_ctr_drbg_reseed(drbg,
			entropy, length,
			additional_input, additional_input_length);
		if (ret) {
			nist_zeroize(entropy, sizeof(entropy));
			return ret;
		}

		length = buffer_length;
		if (length > NIST_BLOCK_OUTLEN_BYTES)
			length = NIST_BLOCK_OUTLEN_BYTES;

		ret = nist_ctr_drbg_generate(drbg,
			p, length,
			NULL, 0);
		if (ret) {
			nist_zeroize(entropy, sizeof(entropy));
			return ret;
		}
	}

	nist_zeroize(entropy, sizeof(entropy));

	return 0;
}

void
nist_rbg()
{
	NIST_CTR_DRBG drbg;
	struct stat outstat;
	long long total;
	ssize_t len;
	char *buffer;
	int i, n;
	int32_t buflen, reseed_length = 0;
	void *p = (void *)&nist_rbg;

	nist_ctr_initialize();

	if (fstat(STDOUT_FILENO, &outstat))
		return;

	buflen = outstat.st_blksize;
	if (1024 > buflen)
		buflen = 1024;
		
	buffer = (char *)malloc(buflen);
	if (!buffer)
		return;	

	if (nist_rbg_instantiate(&drbg, &p, sizeof(p))) {
		free(buffer);
		return;
	}

	for (total = 0; !size || total < size; total += buflen) {
		n = buflen;
		if (size && n > size - total)
			n = size - total;

		if (nist_rbg_generate(&drbg, buffer, n, NULL, 0)) {
			free(buffer);
			return;
		}

		/* Reseed every 100,000 bytes */
		reseed_length += n;
		if (reseed_length  > 100000) {
			nist_rbg_reseed(&drbg);
			reseed_length = 0;
		}

		for (i = 0; i < n; i += len) {
			len = write(STDOUT_FILENO, buffer + i, n - i);
			if (len < 1) {
				free(buffer);
				return;
			}
		}
	}

	free(buffer);
}

