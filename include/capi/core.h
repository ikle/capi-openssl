/*
 * Crypto API Core
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_CORE_H
#define CAPI_CORE_H  1

#include <stddef.h>

/*
 * Argument prov represents the cryptographic provider to use; if it is
 * NULL, then the default provider is used.
 *
 * Argument name represents the name of the key container; if it is NULL,
 * then a temporary container is used.
 *
 * Function capi_alloc creates a cryptographic context. Function capi_free
 * frees the cryptographic context.
 */

struct capi *capi_alloc (const char *prov, const char *name);
void capi_free (struct capi *o);

struct capi_key  *capi_get_key  (struct capi *o);
struct capi_cert *capi_get_cert (struct capi *o);

#endif  /* CAPI_CORE_H */
