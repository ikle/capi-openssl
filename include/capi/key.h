/*
 * Crypto API Key
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_KEY_H
#define CAPI_KEY_H  1

#include <capi/core.h>

struct capi_key *capi_key_alloc (struct capi *o, ...);
void capi_key_free (struct capi_key *o);

size_t capi_key_size (struct capi_key *o);

int capi_key_eq (const struct capi_key *a, const struct capi_key *b);

struct capi_key *capi_key_derive (struct capi_key *o, struct capi_key *peer);

#endif  /* CAPI_KEY_H */
