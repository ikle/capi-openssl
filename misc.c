/*
 * Crypto API Miscelaneous Utilites
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"

char *str_printf_va (const char *fmt, va_list ap)
{
	va_list args;
	char *s;
	int len;

	va_copy (args, ap);
	len = vsnprintf (NULL, 0, fmt, args);
	va_end (args);

	if (len < 0)
		return NULL;

	if ((s = malloc (len + 1)) == NULL)
		return NULL;

	vsnprintf (s, len + 1, fmt, ap);
	return s;
}

char *str_printf (const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start (ap, fmt);
	s = str_printf_va (fmt, ap);
	va_end (ap);

	return s;
}

FILE *file_open_va (const char *mode, const char *fmt, va_list ap)
{
	const char *home;
	char *path, *p;
	FILE *f;

	if ((path = str_printf_va (fmt, ap)) == NULL)
		return NULL;

	if (strncmp (path, "~/", 2) == 0) {
		if ((home = getenv ("HOME")) == NULL ||
		    (p = str_printf ("%s/%s", home, path + 2)) == NULL)
			goto no_home;

		free (path);
		path = p;
	}

	f = fopen (path, mode);
	free (path);
	return f;
no_home:
	free (path);
	return NULL;
}

FILE *file_open (const char *mode, const char *fmt, ...)
{
	va_list ap;
	FILE *f;

	va_start (ap, fmt);
	f = file_open_va (mode, fmt, ap);
	va_end (ap);

	return f;
}
