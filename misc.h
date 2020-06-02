/*
 * Crypto API Miscelaneous Utilites
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef CAPI_MISC_H
#define CAPI_MISC_H  1

#include <stdio.h>

char *str_printf_va (const char *fmt, va_list ap);
char *str_printf    (const char *fmt, ...);

FILE *file_open_va (const char *mode, const char *fmt, va_list ap);
FILE *file_open    (const char *mode, const char *fmt, ...);

#endif  /* CAPI_MISC_H */
