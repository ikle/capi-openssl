/*
 * Crypto API Certificate Store
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_STORE_H
#define CAPI_STORE_H  1

#include <stddef.h>

/*
 * The function capi_store_alloc creates the new certificate store object.
 * If name is NULL then the default trusted certificate store is used,
 * overwise trusted certificates loaded from named store.
 *
 * The function capi_store_free destroys certificate store object.
 *
 * The function capi_store_reset resets internal certificate store state to
 * initial state. This function remove all untrusted certificates from
 * certificate store.
 *
 * The function capi_store_add_cert adds DER encoded untrusted certificate
 * into certificate store. Returns 1 on success, zero overwise.
 *
 * The function capi_store_add_host adds peer host name to verify. Only
 * single host name may be supported. Returns 1 on success, zero overwise.
 *
 * The function capi_store_add_mail adds peer e-mail address name to verify.
 * Only single address may be supported. Returns 1 on success, zero overwise.
 *
 * The function capi_store_add_ip adds peer binary-encoded IPv4 or IPv6
 * address to verify. Only single address may be supported. Returns 1 on
 * success, zero overwise.
 *
 * The capi_store_verify verifies DER encoded certificate agains certificate
 * store. Returns 1 on success, zero overwise.
 */
struct capi_store *capi_store_alloc (const char *name);
void capi_store_free (struct capi_store *o);

void capi_store_reset (struct capi_store *o);

int capi_store_add_cert (struct capi_store *o, const void *data, size_t len);
int capi_store_add_host (struct capi_store *o, const char *host);
int capi_store_add_mail (struct capi_store *o, const char *mail);
int capi_store_add_ip   (struct capi_store *o, const void *addr, size_t len);

int capi_store_verify (struct capi_store *o, const void *data, size_t len);

#endif  /* CAPI_STORE_H */
