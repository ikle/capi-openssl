/*
 * Crypto API Certificate
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include <capi/cert.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "misc.h"

static FILE *capi_open_cert (struct capi *o, const char *name)
{
	FILE *f;

	if ((f = file_open ("rb", "%s.pem", name)) == NULL &&
	    (f = file_open ("rb", "~/.pki/certs/%s.pem", name)) == NULL &&
	    (f = file_open ("rb", "/etc/ssl/certs/%s.pem", name)) == NULL)
		return NULL;

	return f;
}

static STACK_OF (X509) *capi_load_cert (struct capi *o, const char *name)
{
	FILE *f;
	STACK_OF (X509) *chain;
	X509 *cert;

	if ((f = capi_open_cert (o, name)) == NULL)
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

struct capi_cert *capi_cert_alloc (struct capi *o, const char *name)
{
	return (void *) capi_load_cert (o, name);
}

void capi_cert_free (struct capi_cert *o)
{
	STACK_OF (X509) *chain = (void *) o;

	if (o == NULL)
		return;

	sk_X509_pop_free (chain, X509_free);
}
