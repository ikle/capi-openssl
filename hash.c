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
#include <openssl/evp.h>

#include "core-internal.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_MD_CTX_new()	EVP_MD_CTX_create ()
#define EVP_MD_CTX_free(o)	EVP_MD_CTX_destroy (o)
#define EVP_MD_CTX_reset(o)	EVP_MD_CTX_cleanup (o)

#endif

struct capi_hash {
	struct capi *capi;
	EVP_MD_CTX  *ctx;
};

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

static EVP_MD_CTX *md_ctx_clone (struct capi_hash *o)
{
	EVP_MD_CTX *c;

	if ((c = EVP_MD_CTX_new ()) == NULL)
		return NULL;

	if (EVP_MD_CTX_copy_ex (c, o->ctx))
		return c;

	EVP_MD_CTX_free (c);
	return NULL;
}

struct capi_hash *capi_hash_clone (struct capi_hash *o)
{
	struct capi_hash *copy;

	if ((copy = malloc (sizeof (*copy))) == NULL)
		return NULL;

	copy->capi = o->capi;

	if ((copy->ctx = md_ctx_clone (o)) != NULL)
		return copy;

	free (copy);
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
	const EVP_MD *md = EVP_MD_CTX_md (o->ctx);

	return EVP_MD_CTX_reset (o->ctx) &&
	       EVP_DigestInit_ex (o->ctx, md, NULL);
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
	return count;
}

int capi_hash_sign (struct capi_hash *o, void *sign, size_t len)
{
	EVP_MD_CTX *c;
	int ok;

	const unsigned size = EVP_PKEY_size (o->capi->key);
	unsigned char buf[size];
	unsigned count;

	if (sign == NULL)
		return EVP_MD_CTX_size (o->ctx);

	ok = (c = md_ctx_clone (o)) != NULL &&
	     EVP_SignFinal (c, buf, &count, o->capi->key) == 1;

	EVP_MD_CTX_free (c);

	if (!ok)
		return 0;

	if (count > len)
		count = len;

	memcpy (sign, buf, count);
	return count;
}

int capi_hash_verify (struct capi_hash *o, const void *sign, size_t len)
{
	EVP_MD_CTX *c;
	int ok;

	ok = (c = md_ctx_clone (o)) != NULL &&
	     EVP_VerifyFinal (c, sign, len, o->capi->key) == 1;

	EVP_MD_CTX_free (c);
	return ok;
}
