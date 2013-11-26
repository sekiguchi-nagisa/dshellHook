#ifndef DEFINE_H_
#define DEFINE_H_

#include "autogensrc/funcType.h"
#include "autogensrc/funcIndex.h"

#define SAVE_FUNC(funcname) originalFuncTable[FUNC_INDEX(funcname)] = dlsym(RTLD_NEXT, #funcname)
#define FUNC_TYPE(funcname) funcname ## _orig_type

// original error report function type
#define perror_orig_type (void (*)(const char*))
#define strerror_orig_type (char *(*)(int))
#define strerror_r_orig_type (char *(*)(int, char *, size_t))
#define error_orig_type (void (*)(int, int, const char*, ...))

#define __INVOKE_ORIG_FUNC(funcname) (FUNC_TYPE(funcname)(getOriginalFunction(FUNC_INDEX(funcname))))

#endif /* DEFINE_H_ */
