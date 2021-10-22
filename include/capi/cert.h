/*
 * Crypto API Certificate
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_CERT_H
#define CAPI_CERT_H  1

#include <capi/core.h>

struct capi_cert *capi_cert_alloc (struct capi *o, const char *name);
void capi_cert_free (struct capi_cert *o);

#endif  /* CAPI_CERT_H */
