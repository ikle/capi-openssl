/*
 * Crypto API Hash, Message Digest Core
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <capi/hash.h>

#include "capi-hash.h"
#include "capi-key.h"
#include "capi-opts.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline HMAC_CTX *HMAC_CTX_new (void)
{
	HMAC_CTX *o;

	if ((o = malloc (sizeof (*o)) == NULL)
		return NULL;

	HMAC_CTX_init (o);
	return o;
}

static inline void HMAC_CTX_free (HMAC_CTX *o)
{
	HMAC_CTX_cleanup (o);
	free (o);
}

#endif

static const struct capi_opt opts[] = {
	{ CAPI_OPT_KEY, "key",     0 },
	{ CAPI_OPT_BIN, "key-bin", 0 },
	{ CAPI_OPT_HEX, "key-hex", 0 },
	{ CAPI_OPT_STR, "key-str", 0 },
};

static struct capi_hash *
capi_hmac_alloc (struct capi *capi, const char *algo, va_list ap)
{
	const EVP_MD *md;
	struct capi_blob key = { NULL, NULL, 0 };
	struct capi_hash *o;

	if ((md = EVP_get_digestbyname (algo)) == NULL)
		return NULL;

	if (!capi_set_opts (&key, opts, ARRAY_SIZE (opts), ap))
		return NULL;

	if ((o = malloc (sizeof (*o))) == NULL)
		goto no_hash;

	o->capi = capi;
	o->core = &capi_hash_hmac;

	if ((o->hmac = HMAC_CTX_new ()) == NULL)
		goto no_ctx;

	if (!HMAC_Init_ex (o->hmac, key.data, key.len, md, capi->engine))
		goto no_init;

	capi_blob_fini (&key);
	return o;
no_init:
	HMAC_CTX_free (o->hmac);
no_ctx:
	free (o);
no_hash:
	capi_blob_fini (&key);
	return NULL;
}

static void capi_hmac_free (struct capi_hash *o)
{
	HMAC_CTX_free (o->hmac);
	free (o);
}

static int capi_hmac_reset (struct capi_hash *o)
{
	return HMAC_Init_ex (o->hmac, NULL, 0, NULL, o->capi->engine);
}

static int capi_hmac_update (struct capi_hash *o, const void *in, size_t len)
{
	return HMAC_Update (o->hmac, in, len);
}

static int capi_hmac_final (struct capi_hash *o, void *md, size_t len)
{
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned count;

	if (md == NULL)
		return HMAC_size (o->hmac);

	if (!HMAC_Final (o->hmac, buf, &count))
		return 0;

	if (count > len)
		count = len;

	memcpy (md, buf, count);
	OPENSSL_cleanse (buf, sizeof (buf));
	return count;
}

struct capi_hash_core capi_hash_hmac = {
	.alloc	= capi_hmac_alloc,
	.free	= capi_hmac_free,
	.reset	= capi_hmac_reset,
	.update	= capi_hmac_update,
	.final	= capi_hmac_final,
};
