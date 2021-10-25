/*
 * Crypto API Hash Internals
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_HASH_INTERNAL_H
#define CAPI_HASH_INTERNAL_H  1

#include <stddef.h>

#include <openssl/evp.h>

#include "capi-core.h"

struct capi_hash_core;

struct capi_hash {
	struct capi *capi;
	const struct capi_hash_core *core;
	union {
		EVP_MD_CTX *mdc;
	};
};

struct capi_hash_core {
	struct capi_hash *(*alloc) (struct capi *capi, const char *algo);
	void (*free) (struct capi_hash *o);

	int (*reset) (struct capi_hash *o);

	int (*update) (struct capi_hash *o, const void *in, size_t len);
	int (*final)  (struct capi_hash *o, void *out, size_t len);
};

struct capi_hash_core capi_hash_md;

#endif  /* CAPI_HASH_INTERNAL_H */
