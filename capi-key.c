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

#include "capi-key.h"
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
	EVP_PKEY *params;
};

static int param_init (struct param *o, const char *type)
{
	o->params = NULL;

	if (strcmp (type, "ec-p-256") == 0) {
		o->type = EVP_PKEY_EC;
		o->n = NID_X9_62_prime256v1;
	}
	else if (strncmp (type, "ec-", 3) == 0) {
		o->type = EVP_PKEY_EC;
		o->n = OBJ_sn2nid (type + 3);
	}
	else if (strncmp (type, "rsa-", 4) == 0) {
		o->type = EVP_PKEY_RSA;
		o->n = atoi (type + 4);
	}
	else if (strncmp (type, "dsa-", 4) == 0) {
		o->type = EVP_PKEY_DSA;
		o->n = atoi (type + 4);
	}
	else if (strncmp (type, "dh-", 3) == 0) {
		o->type = EVP_PKEY_DH;
		o->n = atoi (type + 3);
	}
	else
		return 0;  /* not implemented */

	return 1;
}

static int param_init_paramgen (struct param *o, EVP_PKEY_CTX *c)
{
	if (EVP_PKEY_paramgen_init (c) <= 0)
		return 0;

	switch (o->type) {
	case EVP_PKEY_EC:
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid (c, o->n) > 0;
	case EVP_PKEY_DSA:
		return EVP_PKEY_CTX_set_dsa_paramgen_bits (c, o->n) > 0;
	case EVP_PKEY_DH:
		return EVP_PKEY_CTX_set_dh_paramgen_prime_len (c, o->n) > 0;
	}

	return 1;
}

static int param_init_keygen (struct param *o, EVP_PKEY_CTX *c)
{
	if (EVP_PKEY_keygen_init (c) <= 0)
		return 0;

	switch (o->type) {
	case EVP_PKEY_RSA:
		return EVP_PKEY_CTX_set_rsa_keygen_bits (c, o->n) > 0;
	}

	return 1;
}

static
int param_init_params (struct param *o, struct capi *capi, const char *type)
{
	EVP_PKEY_CTX *c;

	if (!param_init (o, type))
		return 0;

	if ((c = EVP_PKEY_CTX_new_id (o->type, capi->engine)) == NULL)
		return 0;

	if (!param_init_paramgen (o, c))
		goto no_init;

	EVP_PKEY_paramgen (c, &o->params);
	EVP_PKEY_CTX_free (c);
	return 1;
no_init:
	EVP_PKEY_CTX_free (c);
	return 0;
}

static EVP_PKEY *capi_gen_key (struct capi *o, const char *type)
{
	struct param p;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *c;

	if (!param_init_params (&p, o, type))
		return NULL;

	if ((c = EVP_PKEY_CTX_new (p.params, o->engine)) == NULL)
		return NULL;

	if (!param_init_keygen (&p, c))
		goto no_init;

	EVP_PKEY_keygen (c, &key);

	EVP_PKEY_free(p.params);
	EVP_PKEY_CTX_free (c);
	return key;
no_init:
	EVP_PKEY_CTX_free (c);
	return NULL;
}

struct capi_key *capi_key_alloc (struct capi *capi, const char *type,
				 const char *name)
{
	struct capi_key *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->capi = capi;
	o->type = CAPI_KEY_PKEY;

	o->pkey = (name != NULL) ?
		capi_load_key (capi, name) :
		capi_gen_key (capi, type);

	if (o->pkey == NULL)
		goto no_pkey;

	return o;
no_pkey:
	free (o);
	return NULL;
}

void capi_key_free (struct capi_key *o)
{
	if (o == NULL)
		return;

	if (o->type == CAPI_KEY_RAW)
		OPENSSL_cleanse (o->raw.data, o->raw.len);

	if (o->type == CAPI_KEY_PKEY)
		EVP_PKEY_free (o->pkey);

	free (o);
}

size_t capi_key_size (struct capi_key *o)
{
	switch (o->type) {
	case CAPI_KEY_RAW:	return o->raw.len;
	case CAPI_KEY_PKEY:	return EVP_PKEY_size (o->pkey);
	}

	return 0;
}
