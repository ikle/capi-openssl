/*
 * Crypto API Options Helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include "capi-opts.h"

static int opt_cmp (const void *a, const void *b)
{
	const char *name = a;
	const struct capi_opt *opt = b;

	return strcmp (name, opt->name);
}

int capi_set_opts (void *o, const struct capi_opt *opts, size_t n, va_list ap)
{
	va_list aq;
	const char *name;
	const struct capi_opt *opt;

	unsigned *np;
	struct capi_blob *b;

	for (
		va_copy (aq, ap);
		(name = va_arg (aq, const char *)) != NULL;
		va_copy (ap, aq)
	) {
		opt = bsearch (name, opts, n, sizeof (opts[0]), opt_cmp);
		if (opt == NULL)
			return 1;  /* unknown option, stop processing */

		if (opt->type == CAPI_OPT_NUM) {
			np = o + opt->offset;
			*np = va_arg (aq, unsigned);
			continue;
		}

		b = o + opt->offset;

		if (!capi_blob_init_ng (b, opt->type, aq))
			return 0;  /* error */
	}

	return 1;  /* all options processed */
}
