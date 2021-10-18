/*
 * Crypto API Certificate Store
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <capi/store.h>

struct capi_store {
	X509_STORE *store;
	STACK_OF (X509) *chain;		/* untrusted */
	X509_VERIFY_PARAM *param;
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
	o->param = NULL;
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
	X509_VERIFY_PARAM_free (o->param);
	sk_X509_pop_free (o->chain, X509_free);
	X509_STORE_free (o->store);
	free (o);
}

void capi_store_reset (struct capi_store *o)
{
	sk_X509_pop_free (o->chain, X509_free);
	o->chain = NULL;

	X509_VERIFY_PARAM_free (o->param);
	o->param = NULL;
}

int capi_store_add_cert (struct capi_store *o, const void *data, size_t len)
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

static int param_prepare (struct capi_store *o)
{
	return (o->param != NULL) ||
	       (o->param = X509_VERIFY_PARAM_new ()) != NULL;
}

int capi_store_add_host (struct capi_store *o, const char *host)
{
	if (!param_prepare (o))
		return 0;

	return X509_VERIFY_PARAM_add1_host (o->param, host, 0);
}

int capi_store_add_mail (struct capi_store *o, const char *mail)
{
	if (!param_prepare (o))
		return 0;

	return X509_VERIFY_PARAM_set1_email (o->param, mail, 0);
}

int capi_store_add_ip (struct capi_store *o, const void *addr, size_t len)
{
	if (!param_prepare (o))
		return 0;

	return X509_VERIFY_PARAM_set1_ip (o->param, addr, len);
}

static int get_usage_id (const char *name)
{
	int i = X509_PURPOSE_get_by_sname (name);
	X509_PURPOSE *usage;

	if ((usage = X509_PURPOSE_get0 (i)) == NULL)
		return X509_PURPOSE_ANY;

	return X509_PURPOSE_get_id (usage);
}

int capi_store_add_usage (struct capi_store *o, const char *usage)
{
	if (!param_prepare (o))
		return 0;

	return X509_VERIFY_PARAM_set_purpose (o->param, get_usage_id (usage));
}

static int capi_store_apply_params (struct capi_store *o)
{
	X509_VERIFY_PARAM *param;

	if ((param = X509_STORE_CTX_get0_param (o->ctx)) == NULL)
		return 0;

	(void) X509_VERIFY_PARAM_set_flags (param, X509_V_FLAG_TRUSTED_FIRST);

	return o->param == NULL || X509_VERIFY_PARAM_set1 (param, o->param);
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

	ok = X509_STORE_CTX_init (o->ctx, o->store, cert, o->chain) &&
	     capi_store_apply_params (o) &&
	     X509_verify_cert (o->ctx) == 1;

	X509_free (cert);
	return ok;
}
