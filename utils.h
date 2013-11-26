#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#define FUNC_INDEX(funcname) funcname ## _orig_index
#define FUNC_TYPE(funcname) funcname ## _orig_type

// function type
#define perror_orig_type (void (*)(const char*))
#define strerror_orig_type (char *(*)(int))
#define error_orig_type (void (*)(int, int, const char*, ...))

typedef enum {
	FUNC_INDEX(perror),
	FUNC_INDEX(strerror),
	FUNC_INDEX(error),
	max_index,
} FuncIndex;

#define INVOKE_ORIG_FUNC(funcname) (FUNC_TYPE(funcname)(getOriginalFunction(FUNC_INDEX(funcname))))


void initErrorCodeMap();
void saveOriginalFunction();
void *getOriginalFunction(FuncIndex index);
void reportError(const char *message);

void error_varg(int status, int errnum, const char *format, va_list args);

#endif /* UTILS_H_ */
