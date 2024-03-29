/*
 * Crypto API Hash Internals
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_HASH_INTERNAL_H
#define CAPI_HASH_INTERNAL_H  1

#include <stdarg.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "capi-core.h"

struct capi_hash_core;

struct capi_hash {
	struct capi *capi;
	const struct capi_hash_core *core;
	union {
		EVP_MD_CTX *mdc;
		HMAC_CTX   *hmac;
	};
};

struct capi_hash_core {
	struct capi_hash *(*alloc) (struct capi *capi, const char *algo, va_list ap);
	void (*free) (struct capi_hash *o);

	int (*reset) (struct capi_hash *o);

	int (*update) (struct capi_hash *o, const void *in, size_t len);
	int (*final)  (struct capi_hash *o, void *out, size_t len);
};

struct capi_hash_core capi_hash_md;
struct capi_hash_core capi_hash_hmac;

#endif  /* CAPI_HASH_INTERNAL_H */
