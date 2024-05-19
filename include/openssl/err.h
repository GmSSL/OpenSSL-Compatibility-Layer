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

 // 这个错误实际上极少出现，我们不需要考虑这个问题，只需要保证不触发这个就可以了

 671             if (ERR_GET_LIB(n) == ERR_LIB_PEM
 672                 && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
 673             {
 675                 ERR_clear_error();
 676                 break;
 677             }

*/
#define PEM_R_NO_START_LINE	1

// from openssl/err.h
#define ERR_LIB_NONE            1
#define ERR_LIB_PEM             9


// OpenSSL的错误e中实际上包含了错误所在的LIB的编码，因此给到一个错误号，我们知道这个错误是哪个库发出来的

int ERR_GET_LIB(unsigned long e);
int ERR_GET_REASON(unsigned long e);


/*
// 这里的做法是总是保证ERR_clear_error()会被调用，这很奇怪，可能是我们提供的证书不正确
#define ERR_GET_LIB(e)			((e)?ERR_LIB_PEM:ERR_LIB_PEM)
#define ERR_GET_REASON(e)		((e)?PEM_R_NO_START_LINE:PEM_R_NO_START_LINE)
#define ERR_TXT_STRING			(0)
*/

// 这个是用来干什么的
# define ERR_TXT_STRING          0x02



#ifdef __cplusplus
}
#endif
#endif
