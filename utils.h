#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stddef.h>
#include "define.h"

#define INVOKE_ORIG_FUNC __INVOKE_ORIG_FUNC

void initErrorCodeMap();
void saveOriginalFunction();
void *getOriginalFunction(int index);
void reportError(const char *message);

void error_varg(int status, int errnum, const char *format, va_list args);

#endif /* UTILS_H_ */
