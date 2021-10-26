/*
 * Crypto API TLS PRF
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <capi/hash.h>

#include "capi-hash.h"
#include "capi-prf.h"

struct state {
	struct capi_hash *g;

	const char *label;
	size_t      llen;
	const void *seed;
	size_t      slen;
	size_t      blen;
	size_t      avail;

	unsigned char state[];
};

static int
state_init (struct state *o, struct capi *capi, const char *algo, va_list ap)
{
	if ((o->g = capi_hash_hmac.alloc (capi, algo, ap)) == NULL)
		return 0;

	o->label = va_arg (ap, const char *);
	o->llen  = strlen (o->label);
	o->seed  = va_arg (ap, const void *);
	o->slen  = va_arg (ap, size_t);
	o->blen  = capi_hash_final (o->g, NULL, 0);
	o->avail = 0;

	return 1;
}

static void state_fini (struct state *o)
{
	OPENSSL_cleanse (o->state, o->blen * 2);
	capi_hash_free (o->g);
}

static int state_init_a (struct state *o)
{
	return capi_hash_update (o->g, o->label, o->llen) &&
	       capi_hash_update (o->g, o->seed,  o->slen) &&
	       capi_hash_final  (o->g, o->state, o->blen) &&
	       capi_hash_reset  (o->g);
}

static int state_step_a (struct state *o)
{
	return capi_hash_update (o->g, o->state, o->blen) &&
	       capi_hash_final  (o->g, o->state, o->blen) &&
	       capi_hash_reset  (o->g);
}

static int state_step_p (struct state *o)
{
	return capi_hash_update (o->g, o->state, o->blen) &&
	       capi_hash_update (o->g, o->label, o->llen) &&
	       capi_hash_update (o->g, o->seed,  o->slen) &&
	       capi_hash_final  (o->g, o->state + o->blen, o->blen) &&
	       ((o->avail = o->blen), capi_hash_reset (o->g));
}

static int state_step (struct state *o)
{
	return state_step_a (o) && state_step_p (o);
}

static struct capi_prf *
capi_tls_alloc (struct capi *capi, const char *algo, va_list ap)
{
	struct state s;
	struct capi_prf *o;

	if (!state_init (&s, capi, algo, ap))
		return NULL;

	if ((o = malloc (sizeof (*o) + sizeof (s) + s.blen * 2)) == NULL)
		goto no_ctx;

	o->capi = capi;
	o->core = &capi_prf_tls;

	memcpy (o->state, &s, sizeof (s));

	if (!state_init_a ((void *) o->state))
		goto no_init;

	return o;
no_init:
	free (o);
no_ctx:
	state_fini (&s);
	return NULL;
}

static void capi_tls_free (struct capi_prf *o)
{
	struct state *s = (void *) o->state;

	state_fini (s);
	free (o);
}

static int capi_tls_read (struct capi_prf *o, void *out, size_t len)
{
	struct state *s = (void *) o->state;
	unsigned char *p;
	size_t count;

	for (p = out; len > 0; s->avail -= count, p += count, len -= count) {
		if (s->avail == 0 && !state_step (s))
			return 0;

		count = len < s->avail ? len : s->avail;
		memcpy (p, s->state + s->blen * 2 - s->avail, count);
	}

	return 1;
}

struct capi_prf_core capi_prf_tls = {
	.alloc	= capi_tls_alloc,
	.free	= capi_tls_free,
	.read	= capi_tls_read,
};
