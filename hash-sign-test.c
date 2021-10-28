/*
 * Crypto API Hash Test
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
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
	FILE *f;
	char buf[256], sign[256];
	size_t count, len;

	if (argc != 4) {
		fprintf (stderr, "usage:\n"
				 "\thash-sign-test <key> <algo> <file>\n");
		return 1;
	}

	if ((o = capi_alloc (NULL, NULL, argv[1])) == NULL) {
		fprintf (stderr, "E: cannot allocate CAPI context\n");
		return 1;
	}

	if ((h = capi_hash_alloc (o, argv[2])) == NULL) {
		fprintf (stderr, "E: cannot allocate hash context\n");
		return 1;
	}

	if ((f = fopen (argv[3], "rb")) == NULL) {
		fprintf (stderr, "E: cannot open file\n");
		return 1;
	}

	while ((count = fread (buf, 1, sizeof (buf), f)) > 0)
		capi_hash_update (h, buf, count);

	len = capi_hash_sign (h, sign, sizeof (sign));
	capi_dump (stdout, "sign = ", sign, len);

	printf ("verify = %s\n", capi_hash_verify (h, sign, len) ?
				 "OK" : "FAILED");
	capi_hash_free (h);
	capi_free (o);
	return 0;
}
