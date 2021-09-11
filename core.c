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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <capi/core.h>

#include "misc.h"

struct capi {
	const char *name;  /* key storage name */
	EVP_PKEY *key;
	X509 *cert;
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

static X509 *load_cert (struct capi *o)
{
	FILE *f;
	X509 *cert;

	if ((f = capi_open_cert (o)) == NULL)
		return NULL;

	cert = PEM_read_X509 (f, NULL, NULL, NULL);
	fclose (f);
	return cert;
}

struct capi *capi_alloc (const char *prov, const char *name)
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
	o->cert = NULL;

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

	X509_free (o->cert);
	EVP_PKEY_free (o->key);
	free (o);
}

const struct capi_key *capi_get_key (struct capi *o)
{
	return (void *) o->key;
}

const struct capi_cert *capi_get_cert (struct capi *o)
{
	if (o->cert == NULL && o->name != NULL)
		o->cert = load_cert (o);

	return (void *) o->cert;
}
