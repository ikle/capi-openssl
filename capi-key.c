/*
 * Crypto API Key
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <capi/key.h>

#include "capi-blob.h"
#include "capi-key.h"
#include "capi-opts.h"

struct conf {
	const char *name, *type;
	struct capi_blob raw;
};

static const struct capi_opt opts[] = {
	{ CAPI_OPT_PTR, "name",    offsetof (struct conf, name) },
	{ CAPI_OPT_BIN, "raw-bin", offsetof (struct conf, raw)  },
	{ CAPI_OPT_HEX, "raw-hex", offsetof (struct conf, raw)  },
	{ CAPI_OPT_STR, "raw-str", offsetof (struct conf, raw)  },
	{ CAPI_OPT_PTR, "type",    offsetof (struct conf, type) },
};

struct capi_key *capi_key_alloc_va (struct capi *capi, va_list ap)
{
	struct conf conf = { NULL, NULL, { NULL, NULL, 0 } };
	struct capi_key *o;

	if (!capi_set_opts (&conf, opts, ARRAY_SIZE (opts), ap))
		return NULL;

	if (conf.name != NULL)
		o = capi_key_load (capi, conf.name, ap);
	else
	if (conf.type != NULL)
		o = capi_key_generate (capi, conf.name, ap);
	else
	if ((o = capi_key_raw (capi, conf.raw.len)) != NULL)
		memcpy (o->raw.data, conf.raw.data, conf.raw.len);

	capi_blob_fini (&conf.raw);
	return o;
}

struct capi_key *capi_key_alloc (struct capi *capi, ...)
{
	va_list ap;
	struct capi_key *o;

	va_start (ap, capi);
	o = capi_key_alloc_va (capi, ap);
	va_end (ap);

	return o;
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

int capi_key_eq (const struct capi_key *a, const struct capi_key *b)
{
	if (a->type != b->type)
		return 0;

	if (a->type == CAPI_KEY_RAW)
		return a->raw.len == b->raw.len &&
		       memcmp (a->raw.data, b->raw.data, a->raw.len) == 0;

	if (a->type == CAPI_KEY_PKEY)
		return EVP_PKEY_cmp (a->pkey, b->pkey) == 1;

	return 0;
}
