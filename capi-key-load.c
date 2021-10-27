/*
 * Crypto API Key Loading
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include <capi/key.h>
#include <openssl/pem.h>

#include "capi-core.h"
#include "capi-key.h"
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

struct capi_key *capi_key_load (struct capi *capi, const char *name, va_list ap)
{
	struct capi_key *o;
	FILE *f;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->capi = capi;
	o->type = CAPI_KEY_PKEY;

	if ((f = capi_open_key (capi, name)) == NULL)
		goto no_file;

	if ((o->pkey = PEM_read_PrivateKey (f, NULL, NULL, NULL)) == NULL)
		goto no_pkey;

	fclose (f);
	return o;
no_pkey:
	fclose (f);
no_file:
	free (o);
	return NULL;
}
