/*
 * Crypto API Key Internals
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_KEY_INTERNAL_H
#define CAPI_KEY_INTERNAL_H  1

#include <stddef.h>

#include <openssl/evp.h>

enum capi_key_type {
	CAPI_KEY_RAW,
	CAPI_KEY_PKEY,
};

struct capi_key_raw {
	unsigned len;
	unsigned char data[];
};

struct capi_key {
	struct capi *capi;
	enum capi_key_type type;
	union {
		struct capi_key_raw raw;
		EVP_PKEY *pkey;
	};
};

#endif  /* CAPI_KEY_INTERNAL_H */
