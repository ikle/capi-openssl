/*
 * Crypto API Binary Object Helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_BLOB_H
#define CAPI_BLOB_H  1

#include <stdarg.h>
#include <stddef.h>

enum capi_blob_type {
	CAPI_BLOB_BIN	= 0x10,
	CAPI_BLOB_STR	= 0x11,
	CAPI_BLOB_KEY	= 0x12,
	CAPI_BLOB_HEX	= 0x13,
	CAPI_BLOB_B64	= 0x14,
};

struct capi_blob {
	void *buf;
	const void *data;
	size_t len;
};

int  capi_blob_init (struct capi_blob *o, int type, va_list ap);
void capi_blob_fini (struct capi_blob *o);

#endif  /* CAPI_BLOB_H */
