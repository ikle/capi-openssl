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

	X509_STORE_free (o->store);
	free (o);
}

