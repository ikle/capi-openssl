/*
 * Crypto API Hash
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_HASH_H
#define CAPI_HASH_H  1

#include <capi/core.h>

struct capi_hash *capi_hash_alloc (struct capi *o, const char *algo, ...);
void capi_hash_free (struct capi_hash *o);

int capi_hash_update (struct capi_hash *o, const void *in, size_t len);
int capi_hash_reset  (struct capi_hash *o);
int capi_hash_final  (struct capi_hash *o, void *md, size_t len);

int capi_hash_sign   (struct capi_hash *o, void *sign, size_t len);
int capi_hash_verify (struct capi_hash *o, const void *sign, size_t len);

#endif  /* CAPI_HASH_H */
