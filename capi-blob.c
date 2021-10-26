/*
 * Crypto API Binary Object Helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "capi-blob.h"
#include "capi-key.h"

static int hex_get_byte (const char *p, const char **next)
{
	unsigned b;

	for (; !isxdigit (*p); ++p)
		if (*p == '\0')
			return -1;

	if (!isxdigit (p[1]) || sscanf (p, "%2x", &b) != 1)
		return -1;

	*next = p + 2;
	return b;
}

static size_t hex_get_len (const char *p)
{
	size_t len;

	for (len = 0; hex_get_byte (p, &p) >= 0; ++len) {}

	return len;
}

static void *hex_read (const char *p, void *to)
{
	unsigned char *q;
	int b;

	for (q = to; (b = hex_get_byte (p, &p)) >= 0; ++q)
		*q = b;

	return to;
}

int capi_blob_init (struct capi_blob *o, const char *type, va_list ap)
{
	const struct capi_key *key;

	o->buf = NULL;

	if (strcmp (type, "bin") == 0) {
		o->data = va_arg (ap, const void *);
		o->len  = va_arg (ap, unsigned);
		return 1;
	}

	if (strcmp (type, "hex") == 0) {
		o->data = va_arg (ap, const char *);
		o->len  = hex_get_len (o->data);

		if ((o->buf = malloc (o->len)) == NULL)
			return -1;

		o->data = hex_read (o->data, o->buf);
		return 1;
	}

	if (strcmp (type, "key") == 0) {
		key = va_arg (ap, const struct capi_key *);

		if (key->type != CAPI_KEY_RAW)
			return 0;

		o->len  = key->raw.len;
		o->data = key->raw.data;
		return 1;
	}

	if (strcmp (type, "str") == 0) {
		o->data = va_arg (ap, const char *);
		o->len  = strlen (o->data);
		return 1;
	}

	return 0;
}

void capi_blob_fini (struct capi_blob *o)
{
	if (o->buf == NULL)
		return;

	OPENSSL_cleanse (o->buf, o->len);
	free (o->buf);
}
