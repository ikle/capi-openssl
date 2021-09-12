/*
 * Crypto Random Number API
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>

 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include <capi/random.h>

struct capi_random {
	struct capi *core;
	unsigned long long state;
};

struct capi_random *capi_random_alloc (struct capi *core)
{
	struct capi_random *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->core  = core;
	o->state = 1;

	return o;
}

void capi_random_free (struct capi_random *o)
{
	if (o == NULL)
		return;

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
	return 1;
}

static int secure_random (struct capi_random *o, void *data, size_t len)
{
	return RAND_bytes (data, len) == 1;
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
