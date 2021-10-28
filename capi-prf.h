/*
 * Crypto API PRF Internals
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_PRF_INTERNAL_H
#define CAPI_PRF_INTERNAL_H  1

#include <stdarg.h>
#include <stddef.h>

#include "capi-core.h"

struct capi_prf_core;

struct capi_prf {
	struct capi *capi;
	const struct capi_prf_core *core;
	unsigned char state[];
};

struct capi_prf_core {
	struct capi_prf *(*alloc) (struct capi *capi, const char *algo, va_list ap);
	void (*free) (struct capi_prf *o);

	int (*read) (struct capi_prf *o, void *out, size_t len);
};

struct capi_prf_core capi_prf_tls;

#endif  /* CAPI_PRF_INTERNAL_H */
