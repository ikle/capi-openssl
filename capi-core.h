/*
 * Crypto API Core Internals
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_CORE_INTERNAL_H
#define CAPI_CORE_INTERNAL_H  1

#include <stddef.h>

#include <openssl/engine.h>

struct capi_cert;
struct capi_key;

struct capi {
	ENGINE *engine;
	const char *type;		/* key type			*/
	const char *name;		/* key storage name		*/
	struct capi_key *key, *flash;	/* private and ephemeral keys	*/
	struct capi_cert *chain;	/* key certificate chain	*/
};

#endif  /* CAPI_CORE_INTERNAL_H */
