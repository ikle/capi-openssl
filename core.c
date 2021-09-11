/*
 * Crypto API Core
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <capi/core.h>
#include <capi/store.h>

#include "misc.h"

struct capi {
	const char *name;  /* key storage name */
	EVP_PKEY *key;
	STACK_OF (X509) *chain;

	const char *cadir;
	struct capi_store *store;
	X509_STORE_CTX *store_c;
};

static FILE *capi_open_key (struct capi *o)
{
	FILE *f;

	if ((f = file_open ("rb", "%s.key", o->name)) == NULL &&
	    (f = file_open ("rb", "~/.pki/private/%s.pem", o->name)) == NULL &&
	    (f = file_open ("rb", "/etc/ssl/private/%s.pem", o->name)) == NULL)
		return NULL;

	return f;
}

static FILE *capi_open_cert (struct capi *o)
{
	FILE *f;

	if ((f = file_open ("rb", "%s.pem", o->name)) == NULL &&
	    (f = file_open ("rb", "~/.pki/certs/%s.pem", o->name)) == NULL &&
	    (f = file_open ("rb", "/etc/ssl/certs/%s.pem", o->name)) == NULL)
		return NULL;

	return f;
}

static EVP_PKEY *load_key (struct capi *o)
{
	FILE *f;
	EVP_PKEY *key;

	if ((f = capi_open_key (o)) == NULL)
		return NULL;

	key = PEM_read_PrivateKey (f, NULL, NULL, NULL);
	fclose (f);
	return key;
}

static STACK_OF (X509) *load_cert_chain (struct capi *o)
{
	FILE *f;
	STACK_OF (X509) *chain;
	X509 *cert;

	if ((f = capi_open_cert (o)) == NULL)
		return NULL;

	if ((chain = sk_X509_new_null ()) == NULL)
		goto no_chain;

	ERR_set_mark ();

	while ((cert = PEM_read_X509 (f, NULL, NULL, NULL)) != NULL)
		if (!sk_X509_push (chain, cert))
			goto no_push;

	ERR_pop_to_mark ();
	fclose (f);
	return chain;
no_push:
	X509_free (cert);
	sk_X509_pop_free (chain, X509_free);
no_chain:
	fclose (f);
	return NULL;
}

struct capi *capi_alloc (const char *prov, const char *store, const char *name)
{
	struct capi *o;

	if (prov != NULL)
		return NULL;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OpenSSL_add_all_algorithms ();
	OPENSSL_config (NULL);
#endif
	o->name = name;
	o->key  = NULL;
	o->chain = NULL;

	o->cadir = store;
	o->store = NULL;
	o->store_c = NULL;

	if (name != NULL && (o->key = load_key (o)) == NULL)
		goto no_key;

	return o;
no_key:
	free (o);
	return NULL;
}

void capi_free (struct capi *o)
{
	if (o == NULL)
		return;

	X509_STORE_CTX_free (o->store_c);
	capi_store_free (o->store);
	sk_X509_pop_free (o->chain, X509_free);
	EVP_PKEY_free (o->key);
	free (o);
}

const struct capi_key *capi_get_key (struct capi *o)
{
	return (void *) o->key;
}

const struct capi_certs *capi_get_certs (struct capi *o)
{
	if (o->chain == NULL && o->name != NULL)
		o->chain = load_cert_chain (o);

	return (void *) o->chain;
}

static X509 *get_cert_at (struct capi *o, int i)
{
	STACK_OF (X509) *chain;
	int n;

	if ((chain = (void *) capi_get_certs (o)) == NULL)
		return NULL;

	if ((n = sk_X509_num (chain)) <= 0 || i >= n)
		return NULL;

	return sk_X509_value (chain, i);
}

const struct capi_cert *capi_get_cert (struct capi *o)
{
	return (void *) get_cert_at (o, 0);
}

int capi_read_cert (struct capi *o, int i, void *data, size_t len)
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

static int verify_cert (struct capi *o, X509 *cert, STACK_OF (X509) *chain)
{
	X509_STORE *store;

	if (o->store_c == NULL) {
		if (o->store == NULL &&
		    (o->store = capi_store_alloc (o->cadir)) == NULL)
			return 0;

		if ((o->store_c = X509_STORE_CTX_new ()) == NULL)
			return 0;
	}
	else
		X509_STORE_CTX_cleanup (o->store_c);

	store = (void *) o->store;

	if (!X509_STORE_CTX_init (o->store_c, store, cert, chain))
		return 0;

	return X509_verify_cert (o->store_c);
}

int capi_push_cert (struct capi *o, const void *data, size_t len)
{
	STACK_OF (X509) *chain;
	X509 *cert;
	const unsigned char *p = data;

	if ((chain = (void *) capi_get_certs (o)) == NULL)
		return 0;

	if ((cert = d2i_X509 (NULL, &p, len)) == NULL)
		return 0;

	if (!verify_cert (o, cert, chain))
		goto error;

	if (sk_X509_push (chain, cert))
		return 1;
error:
	X509_free (cert);
	return 0;
}
