/*
 * Crypto API Hash, Message Digest Core
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <capi/hash.h>

#include "capi-hash.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_MD_CTX_new()        EVP_MD_CTX_create ()
#define EVP_MD_CTX_free(o)      EVP_MD_CTX_destroy (o)

#endif

static struct capi_hash *
capi_md_alloc (struct capi *capi, const char *algo, va_list ap)
{
	const EVP_MD *md;
	struct capi_hash *o;

	if ((md = EVP_get_digestbyname (algo)) == NULL)
		return NULL;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->capi = capi;
	o->core = &capi_hash_md;

	if ((o->mdc = EVP_MD_CTX_new ()) == NULL)
		goto no_ctx;

	if (!EVP_DigestInit_ex (o->mdc, md, capi->engine))
		goto no_init;

	return o;
no_init:
	EVP_MD_CTX_free (o->mdc);
no_ctx:
	free (o);
	return NULL;
}

static void capi_md_free (struct capi_hash *o)
{
	EVP_MD_CTX_free (o->mdc);
	free (o);
}

static int capi_md_reset (struct capi_hash *o)
{
	return EVP_DigestInit_ex (o->mdc, NULL, o->capi->engine);
}

static int capi_md_update (struct capi_hash *o, const void *in, size_t len)
{
	return EVP_DigestUpdate (o->mdc, in, len);
}

static int capi_md_final (struct capi_hash *o, void *md, size_t len)
{
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned count;

	if (md == NULL)
		return EVP_MD_CTX_size (o->mdc);

	if (!EVP_DigestFinal_ex (o->mdc, buf, &count))
		return 0;

	if (count > len)
		count = len;

	memcpy (md, buf, count);
	OPENSSL_cleanse (buf, sizeof (buf));
	return count;
}

struct capi_hash_core capi_hash_md = {
	.alloc	= capi_md_alloc,
	.free	= capi_md_free,
	.reset	= capi_md_reset,
	.update	= capi_md_update,
	.final	= capi_md_final,
};
