/*
 * Crypto API Store
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <openssl/x509_vfy.h>

#include <capi/store.h>

struct capi_store *capi_store_alloc (const char *name)
{
	X509_STORE *o;
	int status;

	if ((o = X509_STORE_new ()) == NULL)
		return NULL;

	status = name == NULL ? X509_STORE_set_default_paths (o) :
				X509_STORE_load_locations (o, NULL, name);
	if (!status)
		goto no_paths;

	return (void *) o;
no_paths:
	X509_STORE_free (o);
	return NULL;
}

void capi_store_free (struct capi_store *store)
{
	X509_STORE *o = (void *) store;

	if (o == NULL)
		return;

	X509_STORE_free (o);
}

