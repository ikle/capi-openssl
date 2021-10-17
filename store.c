/*
 * Crypto API Certificate Store
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include <openssl/x509_vfy.h>

#include <capi/store.h>

struct capi_store {
	X509_STORE *store;
	STACK_OF (X509) *chain;		/* untrusted */
	X509_STORE_CTX *ctx;
};

struct capi_store *capi_store_alloc (const char *name)
{
	struct capi_store *o;
	int status;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if ((o->store = X509_STORE_new ()) == NULL)
		goto no_store;

	status = name == NULL ? X509_STORE_set_default_paths (o->store) :
				X509_STORE_load_locations (o->store, NULL, name);
	if (!status)
		goto no_paths;

	o->chain = NULL;
	o->ctx   = NULL;

	return o;
no_paths:
	X509_STORE_free (o->store);
no_store:
	free (o);
	return NULL;
}

void capi_store_free (struct capi_store *o)
{
	if (o == NULL)
		return;

	X509_STORE_CTX_free (o->ctx);
	sk_X509_pop_free (o->chain, X509_free);
	X509_STORE_free (o->store);
	free (o);
}

void capi_store_reset (struct capi_store *o)
{
	sk_X509_pop_free (o->chain, X509_free);
	o->chain = NULL;
}

int capi_store_add (struct capi_store *o, const void *data, size_t len)
{
	const unsigned char *p = data;
	X509 *cert;

	if (o->chain == NULL && (o->chain = sk_X509_new_null ()) == NULL)
		return 0;

	if ((cert = d2i_X509 (NULL, &p, len)) == NULL)
		return 0;

	if (sk_X509_push (o->chain, cert))
		return 1;

	X509_free (cert);
	return 0;
}

int capi_store_verify (struct capi_store *o, const void *data, size_t len)
{
	const unsigned char *p = data;
	X509 *cert;
	int ok;

	if (o->ctx == NULL) {
		if ((o->ctx = X509_STORE_CTX_new ()) == NULL)
			return 0;
	}
	else
		X509_STORE_CTX_cleanup (o->ctx);

	if ((cert = d2i_X509 (NULL, &p, len)) == NULL)
		return 0;

	if (!X509_STORE_CTX_init (o->ctx, o->store, cert, o->chain))
		return 0;

	ok = X509_verify_cert (o->ctx) == 1;

	X509_free (cert);
	return ok;
}
