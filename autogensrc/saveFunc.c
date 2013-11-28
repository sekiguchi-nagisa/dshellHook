#define _GNU_SOURCE
#include "../define.h"
#include <dlfcn.h>

// auto generated source file
#define SAVE_FUNC(funcname) originalFuncTable[FUNC_INDEX(funcname)] = dlsym(RTLD_NEXT, #funcname)
void saveFuncs(void **originalFuncTable)
{
	SAVE_FUNC(perror);
	SAVE_FUNC(strerror);
	SAVE_FUNC(strerror_r);
	SAVE_FUNC(error);
	SAVE_FUNC(mmap);
	SAVE_FUNC(mmap64);
}
