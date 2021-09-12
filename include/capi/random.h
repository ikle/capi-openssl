/*
 * Crypto Random Number API
 *
 * Copyright (c) 2017-2021 Alexei A. Smekalkine <ikle@ikle.ru>

 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_RANDOM_H
#define CAPI_RANDOM_H  1

#include <capi/core.h>

/*
 * The function capi_random_alloc allocates random number generator
 * state using specified CAPI state provider. If CAPI state does not
 * provided then simple, non-cryptographically secure pseudo random
 * generator created.
 *
 * The function capi_random_free frees random number generator state.
 *
 * The function capi_randon_seed sets simple generator to an initial
 * known state or adds enthropy to CSPRNG. True, non-deterministic
 * random generator silently ignore seed, as it does not have any
 * predictable state.
 *
 * The function capi_random generates the len bytes of random (in case
 * of true RNG) or pseudo random bytes.
 */
struct capi_random *capi_random_alloc (struct capi *core);
void capi_random_free (struct capi_random *o);

int capi_randon_seed (struct capi_random *o, const void *data, size_t len);
int capi_random (struct capi_random *o, void *data, size_t len);

#endif  /* CAPI_RANDOM_H */
