/*
 * Crypto API Key
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <capi/key.h>

#include "capi-key.h"

struct capi_key *
capi_key_alloc_va (struct capi *capi, const char *type, va_list ap)
{
	if (strcmp (type, "ref") == 0)
		return capi_key_load (capi, va_arg (ap, const char *));

	return capi_key_generate (capi, type);
}

struct capi_key *capi_key_alloc (struct capi *capi, const char *type, ...)
{
	va_list ap;
	struct capi_key *o;

	va_start (ap, type);
	o = capi_key_alloc_va (capi, type, ap);
	va_end (ap);

	return o;
}

void capi_key_free (struct capi_key *o)
{
	if (o == NULL)
		return;

	if (o->type == CAPI_KEY_RAW)
		OPENSSL_cleanse (o->raw.data, o->raw.len);

	if (o->type == CAPI_KEY_PKEY)
		EVP_PKEY_free (o->pkey);

	free (o);
}

size_t capi_key_size (struct capi_key *o)
{
	switch (o->type) {
	case CAPI_KEY_RAW:	return o->raw.len;
	case CAPI_KEY_PKEY:	return EVP_PKEY_size (o->pkey);
	}

	return 0;
}
