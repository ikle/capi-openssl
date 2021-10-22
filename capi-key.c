/*
 * Crypto API Key
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <capi/key.h>

#include "core-internal.h"
#include "misc.h"

static FILE *capi_open_key (struct capi *o, const char *name)
{
	FILE *f;

	if ((f = file_open ("rb", "%s.key", name)) == NULL &&
	    (f = file_open ("rb", "~/.pki/private/%s.pem", name)) == NULL &&
	    (f = file_open ("rb", "/etc/ssl/private/%s.pem", name)) == NULL)
		return NULL;

	return f;
}

static EVP_PKEY *capi_load_key (struct capi *o, const char *name)
{
	FILE *f;
	EVP_PKEY *key;

	if ((f = capi_open_key (o, name)) == NULL)
		return NULL;

	key = PEM_read_PrivateKey (f, NULL, NULL, NULL);
	fclose (f);
	return key;
}

struct param {
	int type, n;
};

static int param_init (struct param *o, const char *name)
{
	if (strcmp (name, "ec-p-256") == 0) {
		o->type = EVP_PKEY_EC;
		o->n = NID_X9_62_prime256v1;
	}
	else if (strncmp (name, "ec-", 3) == 0) {
		o->type = EVP_PKEY_EC;
		o->n = OBJ_sn2nid (name + 3);
	}
	else if (strncmp (name, "rsa-", 4) == 0) {
		o->type = EVP_PKEY_RSA;
		o->n = atoi (name + 4);
	}
	else if (strncmp (name, "dsa-", 4) == 0) {
		o->type = EVP_PKEY_DSA;
		o->n = atoi (name + 4);
	}
	else if (strncmp (name, "dh-", 3) == 0) {
		o->type = EVP_PKEY_DH;
		o->n = atoi (name + 3);
	}
	else
		return 0;  /* not implemented */

	return 1;
}

static int param_init_paramgen (struct param *o, EVP_PKEY_CTX *c)
{
	switch (o->type) {
	case EVP_PKEY_EC:
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid (c, o->n) > 0;
	case EVP_PKEY_RSA:
		return EVP_PKEY_CTX_set_rsa_keygen_bits (c, o->n) > 0;
	case EVP_PKEY_DSA:
		return EVP_PKEY_CTX_set_dsa_paramgen_bits (c, o->n) > 0;
	case EVP_PKEY_DH:
		return EVP_PKEY_CTX_set_dh_paramgen_prime_len (c, o->n) > 0;
	}

	return 1;
}

static EVP_PKEY *pkey_make_params (struct capi *o, const char *name)
{
	struct param p;
	EVP_PKEY_CTX *c;
	EVP_PKEY *params = NULL;

	if (!param_init (&p, name))
		return NULL;

	if ((c = EVP_PKEY_CTX_new_id (p.type, o->engine)) == NULL)
		return NULL;

	if (EVP_PKEY_paramgen_init (c) <= 0 || !param_init_paramgen (&p, c))
		goto no_ctx;

	EVP_PKEY_paramgen (c, &params);
	EVP_PKEY_CTX_free (c);
	return params;
no_ctx:
	EVP_PKEY_CTX_free (c);
	return NULL;
}

static EVP_PKEY *capi_gen_key (struct capi *o, const char *type)
{
	EVP_PKEY *params = NULL, *key = NULL;
	EVP_PKEY_CTX *c;

	if ((params = pkey_make_params (o, type)) == NULL)
		return NULL;

	if ((c = EVP_PKEY_CTX_new (params, o->engine)) == NULL)
		return NULL;

	if (EVP_PKEY_keygen_init (c) <= 0)
		goto no_ctx;

	EVP_PKEY_keygen (c, &key);

	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free (c);
	return key;
no_ctx:
	EVP_PKEY_CTX_free (c);
	return NULL;
}

struct capi_key *capi_key_alloc (struct capi *o, const char *type,
				 const char *name)
{
	if (name != NULL)
		return (void *) capi_load_key (o, name);

	return (void *) capi_gen_key (o, type);
}

void capi_key_free (struct capi_key *o)
{
	EVP_PKEY *key = (void *) o;

	EVP_PKEY_free (key);
}

size_t capi_key_size (struct capi_key *o)
{
	return EVP_PKEY_size ((void *) o);
}
