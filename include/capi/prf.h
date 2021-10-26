/*
 * Crypto API Pseudo-Random Function
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_PRF_H
#define CAPI_PRF_H  1

#include <capi/key.h>

struct capi_prf *capi_prf_alloc (struct capi *o, const char *algo, ...);
void capi_prf_free (struct capi_prf *o);

struct capi_key *capi_prf_read (struct capi_prf *o, size_t len);

#endif  /* CAPI_PRF_H */
