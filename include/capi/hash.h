/*
 * Crypto API Hash
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_HASH_H
#define CAPI_HASH_H  1

#include <capi/core.h>

struct capi_hash *capi_hash_alloc (struct capi *o, const char *algo);
struct capi_hash *capi_hash_clone (struct capi_hash *o);
void capi_hash_free (struct capi_hash *o);

size_t capi_hash_size (struct capi_hash *o);

int capi_hash_update (struct capi_hash *o, const void *in, size_t len);
int capi_hash_reset  (struct capi_hash *o);
int capi_hash_final  (struct capi_hash *o, void *md, unsigned len);

int capi_hash_sign   (struct capi_hash *o, void *sign, unsigned len);
int capi_hash_verify (struct capi_hash *o, const void *sign, unsigned len);

#endif  /* CAPI_HASH_H */
