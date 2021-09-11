/*
 * Crypto API Store
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include <openssl/x509_vfy.h>

#include <capi/store.h>

struct capi_store {
	X509_STORE *store;
	STACK_OF (X509) *chain;		/* untrusted */
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

	sk_X509_pop_free (o->chain, X509_free);
	X509_STORE_free (o->store);
	free (o);
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
