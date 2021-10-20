/*
 * Crypto API Core
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_CORE_H
#define CAPI_CORE_H  1

#include <stddef.h>

/*
 * The function capi_alloc creates a cryptographic context in specified
 * provider with specifier key type and key container name.
 *
 * - The argument prov specifies the cryptographic provider to use; if it
 *   is NULL then the default provider is used.
 *
 * - The argument type specifies the key type to be used with created
 *   cryptographic context; if it is NULL then the default key type will
 *   be used.
 *
 * - The argument name specifies the name of the key container; if it is
 *   NULL and type is not then a temporary container is used of specified
 *   type; if both type and name is NULL then no keys available with
 *   created cryptographic context.
 *
 * The function capi_free frees the cryptographic context.
 */

struct capi *capi_alloc (const char *prov, const char *type, const char *name);
void capi_free (struct capi *o);

const struct capi_key  *capi_get_key  (struct capi *o);
const struct capi_cert *capi_get_cert (struct capi *o);

int capi_read_cert (struct capi *o, int i, void *data, size_t len);

#endif  /* CAPI_CORE_H */
