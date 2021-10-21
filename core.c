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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <capi/core.h>

#include "misc.h"

struct capi {
	const char *name;  /* key storage name */
	EVP_PKEY *private, *flash;
	STACK_OF (X509) *chain;
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

static EVP_PKEY *generate_key (struct capi *o)
{
	return NULL;  /* not implemented yet */
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

struct capi *capi_alloc (const char *prov, const char *type, const char *name)
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
	o->name    = name;
	o->private = NULL;
	o->flash   = NULL;
	o->chain   = NULL;

	if (name != NULL) {
		if ((o->private = load_key (o)) == NULL)
			goto no_key;
	}
	else if (type != NULL) {
		if ((o->private = generate_key (o)) == NULL)
			goto no_key;
	}

	return o;
no_key:
	free (o);
	return NULL;
}

void capi_free (struct capi *o)
{
	if (o == NULL)
		return;

	sk_X509_pop_free (o->chain, X509_free);
	EVP_PKEY_free (o->flash);
	EVP_PKEY_free (o->private);
	free (o);
}

const struct capi_key *capi_get_key (struct capi *o)
{
	return (void *) o->private;
}

const struct capi_cert *capi_get_cert (struct capi *o)
{
	if (o->chain == NULL && o->name != NULL)
		o->chain = load_cert_chain (o);

	return (void *) o->chain;
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

	if (o->flash == NULL && (o->flash = generate_key (o)) == NULL)
		return 0;

	if (X509_PUBKEY_set (&key, o->flash) != 1)
		return 0;

	if ((n = i2d_X509_PUBKEY (key, NULL)) <= len)
		i2d_X509_PUBKEY (key, &p);

	X509_PUBKEY_free (key);
	return n;
}
