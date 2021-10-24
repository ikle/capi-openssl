/*
 * Crypto API Hash
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <capi/hash.h>
#include <capi/key.h>

#include "capi-hash.h"
#include "capi-key.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_MD_CTX_new()	EVP_MD_CTX_create ()
#define EVP_MD_CTX_free(o)	EVP_MD_CTX_destroy (o)
#define EVP_MD_CTX_reset(o)	EVP_MD_CTX_cleanup (o)

#endif

struct capi_hash *capi_hash_alloc (struct capi *capi, const char *algo)
{
	const EVP_MD *md;
	struct capi_hash *o;

	if ((md = EVP_get_digestbyname (algo)) == NULL)
		return NULL;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->capi = capi;

	if ((o->ctx = EVP_MD_CTX_new ()) == NULL)
		goto no_ctx;

	if (!EVP_DigestInit_ex (o->ctx, md, capi->engine))
		goto no_init;

	return o;
no_init:
	EVP_MD_CTX_free (o->ctx);
no_ctx:
	free (o);
	return NULL;
}

void capi_hash_free (struct capi_hash *o)
{
	if (o == NULL)
		return;

	EVP_MD_CTX_free (o->ctx);
	free (o);
}

size_t capi_hash_size (struct capi_hash *o)
{
	return EVP_MD_CTX_size (o->ctx);
}

int capi_hash_update (struct capi_hash *o, const void *in, size_t len)
{
	return EVP_DigestUpdate (o->ctx, in, len);
}

int capi_hash_reset (struct capi_hash *o)
{
	return EVP_DigestInit_ex (o->ctx, NULL, o->capi->engine);
}

int capi_hash_final (struct capi_hash *o, void *md, size_t len)
{
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned count;

	if (md == NULL)
		return EVP_MD_CTX_size (o->ctx);

	if (!EVP_DigestFinal_ex (o->ctx, buf, &count))
		return 0;

	if (count > len)
		count = len;

	memcpy (md, buf, count);
	OPENSSL_cleanse (buf, sizeof (buf));
	return count;
}

int capi_hash_sign (struct capi_hash *o, void *sign, size_t len)
{
	const size_t size = capi_key_size (o->capi->key);
	unsigned char buf[size];
	unsigned count;

	if (o->capi->key == NULL || o->capi->key->type != CAPI_KEY_PKEY)
		return 0;

	if (sign == NULL)
		return EVP_MD_CTX_size (o->ctx);

	/*
	 * NOTE: The function EVP_SignFinal makes and finalizes temporal
	 * copy of digest context if it is not already finalized.
	 *
	 * WARNING: This behavior is not documented, but judging by the
	 * analysis of the code, it is supported at least since version
	 * 1.0.0 and up to current 3.0.
	 */
	if (EVP_SignFinal (o->ctx, buf, &count, o->capi->key->pkey) != 1)
		return 0;

	if (count > len)
		count = len;

	memcpy (sign, buf, count);
	return count;
}

int capi_hash_verify (struct capi_hash *o, const void *sign, size_t len)
{
	if (o->capi->key == NULL || o->capi->key->type != CAPI_KEY_PKEY)
		return 0;

	/*
	 * NOTE: The function EVP_VerifyFinal makes and finalizes temporal
	 * copy of digest context if it is not already finalized.
	 *
	 * WARNING: This behavior is not documented, but judging by the
	 * analysis of the code, it is supported at least since version
	 * 1.0.0 and up to current 3.0.
	 */
	return EVP_VerifyFinal (o->ctx, sign, len, o->capi->key->pkey) == 1;
}
