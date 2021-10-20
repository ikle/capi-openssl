/*
 * Crypto API Hash Test
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <capi/hash.h>

#include "misc.h"

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

	if ((o = capi_alloc (NULL, NULL, NULL)) == NULL) {
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

	capi_dump (stdout, "md = ", buf, count);
	return 0;
}
