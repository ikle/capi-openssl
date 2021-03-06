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
void capi_store_free (struct capi_store *store);

#endif  /* CAPI_STORE_H */
