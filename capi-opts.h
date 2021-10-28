/*
 * Crypto API Options Helpers
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_OPTS_H
#define CAPI_OPTS_H  1

#include <stdarg.h>
#include <stddef.h>

#include "capi-blob.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)	(sizeof (a) / sizeof ((a)[0]))
#endif

enum capi_opt_type {
	CAPI_OPT_NUM	= 0x00,			/* unsigned */
	CAPI_OPT_PTR	= 0x01,			/* pointer  */
	CAPI_OPT_BIN	= CAPI_BLOB_BIN,
	CAPI_OPT_STR	= CAPI_BLOB_STR,
	CAPI_OPT_KEY	= CAPI_BLOB_KEY,
	CAPI_OPT_HEX	= CAPI_BLOB_HEX,
	CAPI_OPT_B64	= CAPI_BLOB_B64,
};

struct capi_opt {
	enum capi_opt_type type;
	const char *name;
	size_t offset;
};

int capi_set_opts (void *o, const struct capi_opt *opts, size_t n, va_list ap);

#endif  /* CAPI_OPTS_H */
