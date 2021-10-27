/*
 * Crypto API Core
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <capi/cert.h>
#include <capi/key.h>

#include "capi-core.h"
#include "capi-key.h"
#include "misc.h"

struct capi *capi_alloc (const char *prov, const char *type, const char *name)
{
	struct capi *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OpenSSL_add_all_algorithms ();
	OPENSSL_config (NULL);
#endif
	if (prov == NULL)
		o->engine = NULL;
	else
	if ((o->engine = ENGINE_by_id (prov)) == NULL)
		return NULL;

	o->type    = type;
	o->name    = name;
	o->key     = type != NULL ? capi_key_alloc (o, type, name) : NULL;
	o->flash   = NULL;
	o->chain   = NULL;

	if (o->key == NULL && name != NULL && type != NULL)
		goto no_key;

	return o;
no_key:
	ENGINE_free (o->engine);
	free (o);
	return NULL;
}

void capi_free (struct capi *o)
{
	if (o == NULL)
		return;

	capi_cert_free (o->chain);
	capi_key_free (o->flash);
	capi_key_free (o->key);
	ENGINE_free (o->engine);
	free (o);
}

const struct capi_key *capi_get_key (struct capi *o)
{
	return o->key;
}

const struct capi_cert *capi_get_cert (struct capi *o)
{
	if (o->chain == NULL && o->name != NULL)
		o->chain = capi_cert_alloc (o, o->name);

	return o->chain;
}

static X509 *get_cert_at (struct capi *o, int i)
{
	STACK_OF (X509) *chain;
	int n;

	if ((chain = (void *) capi_get_cert (o)) == NULL)
		return NULL;

	if ((n = sk_X509_num (chain)) <= 0 || i >= n)
		return NULL;

	return sk_X509_value (chain, i);
}

int capi_pull_cert (struct capi *o, int i, void *data, size_t len)
{
	X509 *cert;
	unsigned char *p = data;
	int n;

	if ((cert = get_cert_at (o, i)) == NULL)
		return 0;

	if ((n = i2d_X509 (cert, NULL)) > len)
		return n;

	return i2d_X509 (cert, &p);
}

int capi_pull_key (struct capi *o, void *data, size_t len)
{
	X509_PUBKEY *key = NULL;
	unsigned char *p = data;
	int n;

	if (o->flash == NULL && o->type != NULL &&
	    (o->flash = capi_key_alloc (o, o->type, NULL)) == NULL)
		return 0;

	if (X509_PUBKEY_set (&key, o->flash->pkey) != 1)
		return 0;

	if ((n = i2d_X509_PUBKEY (key, NULL)) <= len)
		i2d_X509_PUBKEY (key, &p);

	X509_PUBKEY_free (key);
	return n;
}
