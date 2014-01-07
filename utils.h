#ifndef UTILS_H_
#define UTILS_H_

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stddef.h>
#include "autogensrc/funcType.h"
#include "autogensrc/funcIndex.h"

#define FUNC_TYPE(funcname) funcname ## _orig_type
#define CALL_ORIG_FUNC(funcname) (FUNC_TYPE(funcname)(getOriginalFunction(FUNC_INDEX(funcname), #funcname)))

void *getOriginalFunction(int index, char *funcname);
void reportError(int errnum, const char *syscallName);

void error_varg(int status, int errnum, const char *format, va_list args);

#endif /* UTILS_H_ */
