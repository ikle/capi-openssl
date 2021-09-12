/*
 * Crypto Random Number API
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>

 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include <capi/hash.h>
#include <capi/random.h>

struct capi_random {
	struct capi *core;

	union {
		unsigned long long state;
		struct capi_hash *prf;
	};
};

struct capi_random *capi_random_alloc (struct capi *core)
{
	struct capi_random *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->core  = core;
	o->state = 1;

	if (core != NULL && (o->prf = capi_hash_alloc (core, "sha256")) == NULL)
		goto no_prf;

	return o;
no_prf:
	free (o);
	return NULL;
}

void capi_random_free (struct capi_random *o)
{
	if (o == NULL)
		return;

	if (o->core != NULL)
		capi_hash_free (o->prf);

	free (o);
}

static int simple_seed (struct capi_random *o, const void *data, size_t len)
{
	if (len > sizeof (o->state))
		len = sizeof (o->state);

	memcpy (&o->state, data, len);
	return 1;
}

static int simple_random (struct capi_random *o, void *data, size_t len)
{
	const unsigned long long a = 0x5DEECE66D, c = 0xB;
	unsigned char *p;

	for (p = data; len > 0; o->state = o->state * a + c, ++p, --len)
		*p = o->state;

	return 1;
}

static int secure_seed (struct capi_random *o, const void *data, size_t len)
{
	RAND_seed (data, len);

	return capi_hash_update (o->prf, data, len);
}

static int secure_random (struct capi_random *o, void *data, size_t len)
{
	const size_t hs = capi_hash_size (o->prf);
	unsigned char h[hs], *p;

	if (RAND_bytes (h, hs) != 1)
		return 0;

	for (p = data; len > hs; p += hs, len -= hs) {
		capi_hash_update (o->prf, h, hs);
		capi_hash_update (o->prf, &len, sizeof (len));
		capi_hash_fetch  (o->prf, h, hs);
		memcpy (p, h, hs);
	}

	capi_hash_update (o->prf, h, hs);
	capi_hash_update (o->prf, &len, sizeof (len));
	capi_hash_fetch  (o->prf, h, hs);
	memcpy (p, h, len);

	return 1;
}

int capi_randon_seed (struct capi_random *o, const void *data, size_t len)
{
	if (o->core != NULL)
		return secure_seed (o, data, len);

	return simple_seed (o, data, len);
}

int capi_random (struct capi_random *o, void *data, size_t len)
{
	if (o->core != NULL)
		return secure_random (o, data, len);

	return simple_random (o, data, len);
}
