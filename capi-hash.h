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

struct capi_hash {
	struct capi *capi;
	EVP_MD_CTX  *ctx;
};

#endif  /* CAPI_HASH_INTERNAL_H */
