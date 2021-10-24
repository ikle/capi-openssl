/*
 * Crypto API Key Derive
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <capi/key.h>
#include <openssl/evp.h>

#include "capi-core.h"
#include "capi-key.h"

struct capi_key *capi_key_derive (struct capi_key *o, struct capi_key *peer)
{
	EVP_PKEY_CTX *c;
	size_t len;
	struct capi_key *skey;

	if (o->type != CAPI_KEY_PKEY || peer->type != CAPI_KEY_PKEY)
		return NULL;

	if ((c = EVP_PKEY_CTX_new (o->pkey, o->capi->engine)) == NULL)
		return NULL;

	if (EVP_PKEY_derive_set_peer (c, peer->pkey) != 1)
		goto no_peer;

	if (EVP_PKEY_derive (c, NULL, &len) != 1)
		goto no_len;

	if ((skey = capi_key_raw (o->capi, len)) == NULL)
		goto no_skey;

	if (EVP_PKEY_derive (c, skey->raw.data, &len) != 1)
		goto no_derive;

	EVP_PKEY_CTX_free (c);
	return skey;
no_derive:
	capi_key_free (skey);
no_skey:
no_len:
no_peer:
	EVP_PKEY_CTX_free (c);
	return NULL;
}
