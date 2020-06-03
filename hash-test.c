/*
 * Crypto API Hash Test
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <capi/hash.h>

static void show_hex (const char *prefix, const char *suffix,
		      const void *data, size_t count, int rev)
{
	const unsigned char *p;
	size_t i;

	fputs (prefix, stdout);

	if (rev)
		for (p = data; count > 0; --count)
			printf ("%02x", p[count - 1]);
	else
		for (p = data, i = 0; i < count; ++i)
			printf ("%02x", p[i]);

	fputs (suffix, stdout);
}

int main (int argc, char *argv[])
{
	struct capi *o;
	struct capi_hash *h;
	char buf[63];	/* small enough to test update series */
			/* non-power of two to test partial block processing */
	size_t count;

	if (argc != 2) {
		fprintf (stderr, "usage:\n\thash-test <algo-name>\n");
		return 1;
	}

	if ((o = capi_alloc (NULL, NULL)) == NULL) {
		fprintf (stderr, "E: cannot allocate CAPI context\n");
		return 1;
	}

	if ((h = capi_hash_alloc (o, argv[1])) == NULL) {
		fprintf (stderr, "E: cannot allocate hash context\n");
		return 1;
	}

	while ((count = fread (buf, 1, sizeof (buf), stdin)) > 0)
		capi_hash_update (h, buf, count);

	count = capi_hash_final (h, buf, sizeof (buf));
	capi_hash_free (h);
	capi_free (o);

	show_hex ("BE digest = ", "\n", buf, count, 0);
	show_hex ("LE digest = ", "\n", buf, count, 1);
	return 0;
}
