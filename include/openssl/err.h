/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OPENSSL_ERR_H
#define OPENSSL_ERR_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


unsigned long ERR_get_error(void);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_error_data(const char **data, int *flags);
unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
void ERR_clear_error(void);



/*
 from nginx src/event/ngx_event_openssl.c

 671             if (ERR_GET_LIB(n) == ERR_LIB_PEM
 672                 && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
 673             {
 675                 ERR_clear_error();
 676                 break;
 677             }

*/
#define PEM_R_NO_START_LINE	1

#define ERR_LIB_PEM			(1)
#define ERR_GET_LIB(e)			((e)?ERR_LIB_PEM:ERR_LIB_PEM)
#define ERR_GET_REASON(e)		((e)?PEM_R_NO_START_LINE:PEM_R_NO_START_LINE)
#define ERR_TXT_STRING			(0)


#ifdef __cplusplus
}
#endif
#endif
