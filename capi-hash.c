/*
 * Crypto API Hash
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include <capi/hash.h>
#include <capi/key.h>

#include "capi-hash.h"
#include "capi-key.h"

struct capi_hash *capi_hash_alloc (struct capi *capi, const char *algo, ...)
{
	va_list ap;
	struct capi_hash *o;

	va_start (ap, algo);

	o = (strncmp (algo, "hmac-" , 5) == 0) ?
		capi_hash_hmac.alloc (capi, algo + 5, ap) :
		capi_hash_md.alloc (capi, algo, ap);

	va_end (ap);
	return o;
}

void capi_hash_free (struct capi_hash *o)
{
	if (o == NULL)
		return;

	o->core->free (o);
}

int capi_hash_update (struct capi_hash *o, const void *in, size_t len)
{
	return o->core->update (o, in, len);
}

int capi_hash_reset (struct capi_hash *o)
{
	return o->core->reset (o);
}

int capi_hash_final (struct capi_hash *o, void *md, size_t len)
{
	return o->core->final (o, md, len);
}

int capi_hash_sign (struct capi_hash *o, void *sign, size_t len)
{
	const size_t size = capi_key_size (o->capi->key);
	unsigned char buf[size];
	unsigned count;

	if (o->capi->key == NULL || o->capi->key->type != CAPI_KEY_PKEY ||
	    o->core != &capi_hash_md)
		return 0;

	if (sign == NULL)
		return size;

	/*
	 * NOTE: The function EVP_SignFinal makes and finalizes temporal
	 * copy of digest context if it is not already finalized.
	 *
	 * WARNING: This behavior is not documented, but judging by the
	 * analysis of the code, it is supported at least since version
	 * 1.0.0 and up to current 3.0.
	 */
	if (EVP_SignFinal (o->mdc, buf, &count, o->capi->key->pkey) != 1)
		return 0;

	if (count > len)
		count = len;

	memcpy (sign, buf, count);
	return count;
}

int capi_hash_verify (struct capi_hash *o, const void *sign, size_t len)
{
	if (o->capi->key == NULL || o->capi->key->type != CAPI_KEY_PKEY ||
	    o->core != &capi_hash_md)
		return 0;

	/*
	 * NOTE: The function EVP_VerifyFinal makes and finalizes temporal
	 * copy of digest context if it is not already finalized.
	 *
	 * WARNING: This behavior is not documented, but judging by the
	 * analysis of the code, it is supported at least since version
	 * 1.0.0 and up to current 3.0.
	 */
	return EVP_VerifyFinal (o->mdc, sign, len, o->capi->key->pkey) == 1;
}
