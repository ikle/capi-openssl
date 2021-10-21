/*
 * Crypto API Hash
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include <capi/hash.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_MD_CTX_new()	EVP_MD_CTX_create ()
#define EVP_MD_CTX_free(o)	EVP_MD_CTX_destroy (o)
#define EVP_MD_CTX_reset(o)	EVP_MD_CTX_cleanup (o)

#endif

struct capi_hash *capi_hash_alloc (struct capi *o, const char *algo)
{
	const EVP_MD *md;
	EVP_MD_CTX *c;

	if ((md = EVP_get_digestbyname (algo)) == NULL)
		return NULL;

	if ((c = EVP_MD_CTX_new ()) == NULL)
		return NULL;

	if (!EVP_DigestInit_ex (c, md, NULL))
		goto no_init;

	return (void *) c;
no_init:
	EVP_MD_CTX_free (c);
	return NULL;
}

struct capi_hash *capi_hash_clone (struct capi_hash *o)
{
	EVP_MD_CTX *c = (void *) o;
	EVP_MD_CTX *copy;

	if ((copy = EVP_MD_CTX_new ()) == NULL)
		return NULL;

	if (EVP_MD_CTX_copy_ex (copy, c))
		return (void *) copy;

	EVP_MD_CTX_free (copy);
	return NULL;
}

void capi_hash_free (struct capi_hash *o)
{
	EVP_MD_CTX *c = (void *) o;

	if (o == NULL)
		return;

	EVP_MD_CTX_free (c);
}

size_t capi_hash_size (struct capi_hash *o)
{
	EVP_MD_CTX *c = (void *) o;

	return EVP_MD_CTX_size (c);
}

int capi_hash_update (struct capi_hash *o, const void *in, size_t len)
{
	EVP_MD_CTX *c = (void *) o;

	return EVP_DigestUpdate (c, in, len);
}

int capi_hash_reset (struct capi_hash *o)
{
	EVP_MD_CTX *c = (void *) o;
	const EVP_MD *md = EVP_MD_CTX_md (c);

	return EVP_MD_CTX_reset (c) && EVP_DigestInit_ex (c, md, NULL);
}

int capi_hash_final (struct capi_hash *o, void *md, unsigned len)
{
	EVP_MD_CTX *c = (void *) o;
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned count;

	if (md == NULL)
		return EVP_MD_CTX_size (c);

	if (!EVP_DigestFinal_ex (c, buf, &count))
		return 0;

	if (count > len)
		count = len;

	memcpy (md, buf, count);
	return count;
}

int capi_hash_sign (struct capi_hash *o, void *sign, unsigned len,
		    const struct capi_key *key)
{
	EVP_MD_CTX *c = (void *) o;
	EVP_PKEY   *k = (void *) key;
	unsigned size = EVP_PKEY_size (k);
	unsigned char buf[size];
	unsigned count;

	if (sign == NULL)
		return EVP_MD_CTX_size (c);

	if (!EVP_SignFinal (c, buf, &count, k))
		return 0;

	if (count > len)
		count = len;

	memcpy (sign, buf, count);
	return count;
}

int capi_hash_verify (struct capi_hash *o, const void *sign, unsigned len,
		      const struct capi_key *key)
{
	EVP_MD_CTX *c = (void *) o;
	EVP_PKEY   *k = (void *) key;

	return EVP_VerifyFinal (c, sign, len, k);
}
