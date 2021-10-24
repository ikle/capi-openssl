/*
 * Crypto API Raw Keys
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include "capi-key.h"

struct capi_key *capi_key_raw (struct capi *capi, unsigned len)
{
	struct capi_key *o;

	if ((o = malloc (sizeof (*o) + len)) == NULL)
		return NULL;

	o->capi = capi;
	o->type = CAPI_KEY_RAW;
	o->raw.len = len;

	return o;
}
