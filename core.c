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

#include "core-internal.h"
#include "misc.h"

static FILE *capi_open_key (struct capi *o)
{
	FILE *f;

	if ((f = file_open ("rb", "%s.key", o->name)) == NULL &&
	    (f = file_open ("rb", "~/.pki/private/%s.pem", o->name)) == NULL &&
	    (f = file_open ("rb", "/etc/ssl/private/%s.pem", o->name)) == NULL)
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

static EVP_PKEY *pkey_make_params (struct capi *o)
{
	int type, n;
	EVP_PKEY_CTX *c;
	EVP_PKEY *params;

	if (strcmp (o->type, "ec-p-256") == 0) {
		type = EVP_PKEY_EC;
		n = NID_X9_62_prime256v1;
	}
	else if (strncmp (o->type, "ec-", 3) == 0) {
		type = EVP_PKEY_EC;
		n = OBJ_sn2nid (o->type + 3);
	}
	else if (strncmp (o->type, "rsa-", 4) == 0) {
		type = EVP_PKEY_RSA;
		n = atoi (o->type + 4);
	}
	else if (strncmp (o->type, "dsa-", 4) == 0) {
		type = EVP_PKEY_DSA;
		n = atoi (o->type + 4);
	}
	else if (strncmp (o->type, "dh-", 3) == 0) {
		type = EVP_PKEY_DH;
		n = atoi (o->type + 3);
	}
	else
		return NULL;  /* not implemented */

	if ((c = EVP_PKEY_CTX_new_id (type, o->engine)) == NULL)
		return NULL;

	if (EVP_PKEY_paramgen_init (c) <= 0)
		goto no_ctx;

	switch (type) {
	case EVP_PKEY_EC:
		n = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (c, n);
		break;
	case EVP_PKEY_RSA:
		n = EVP_PKEY_CTX_set_rsa_keygen_bits (c, n);
		break;
	case EVP_PKEY_DSA:
		n = EVP_PKEY_CTX_set_dsa_paramgen_bits (c, n);
		break;
	case EVP_PKEY_DH:
		n = EVP_PKEY_CTX_set_dh_paramgen_prime_len (c, n);
		break;
	}

	n = n > 0 && EVP_PKEY_paramgen (c, &params) > 0;

	EVP_PKEY_CTX_free (c);
	return n > 0 ? params : NULL;
no_ctx:
	EVP_PKEY_CTX_free (c);
	return NULL;
}

static EVP_PKEY *generate_key (struct capi *o)
{
	EVP_PKEY *params = NULL, *key;
	EVP_PKEY_CTX *c;
	int ok;

	if ((params = pkey_make_params (o)) == NULL)
		return NULL;

	if ((c = EVP_PKEY_CTX_new (params, o->engine)) == NULL)
		return NULL;

	if (EVP_PKEY_paramgen_init (c) <= 0)
		goto no_ctx;

	ok = EVP_PKEY_keygen (c, &key) > 0;

	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free (c);
	return ok ? key : NULL;
no_ctx:
	EVP_PKEY_CTX_free (c);
	return NULL;
}

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
	o->key     = NULL;
	o->flash   = NULL;
	o->chain   = NULL;

	if (name != NULL) {
		if ((o->key = load_key (o)) == NULL)
			goto no_key;
	}
	else if (type != NULL) {
		if ((o->key = generate_key (o)) == NULL)
			goto no_key;
	}

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
	EVP_PKEY_free (o->flash);
	EVP_PKEY_free (o->key);
	ENGINE_free (o->engine);
	free (o);
}

const struct capi_key *capi_get_key (struct capi *o)
{
	return (void *) o->key;
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

	if (o->flash == NULL && (o->flash = generate_key (o)) == NULL)
		return 0;

	if (X509_PUBKEY_set (&key, o->flash) != 1)
		return 0;

	if ((n = i2d_X509_PUBKEY (key, NULL)) <= len)
		i2d_X509_PUBKEY (key, &p);

	X509_PUBKEY_free (key);
	return n;
}
