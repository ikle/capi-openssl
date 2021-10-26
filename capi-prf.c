/*
 * Crypto API Pseudo-Random Function
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <capi/prf.h>

#include "capi-key.h"
#include "capi-prf.h"

struct capi_prf *capi_prf_alloc (struct capi *capi, const char *algo, ...)
{
	va_list ap;
	struct capi_prf *o = NULL;

	va_start (ap, algo);

	if ((strncmp (algo, "tls-", 4) == 0))
		o = capi_prf_tls.alloc (capi, algo + 4, ap);

	va_end (ap);
	return o;
}

void capi_prf_free (struct capi_prf *o)
{
	if (o == NULL)
		return;

	o->core->free (o);
}

struct capi_key *capi_prf_read (struct capi_prf *o, size_t len)
{
	struct capi_key *key;

	if ((key = capi_key_raw (o->capi, len)) == NULL)
		return NULL;

	if (o->core->read (o, key->raw.data, len))
		return key;

	capi_key_free (key);
	return NULL;
}
