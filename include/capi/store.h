/*
 * Crypto API Store
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_STORE_H
#define CAPI_STORE_H  1

#include <stddef.h>

struct capi_store *capi_store_alloc (const char *name);
void capi_store_free (struct capi_store *o);

int capi_store_add (struct capi_store *o, const void *data, size_t len);

#endif  /* CAPI_STORE_H */
