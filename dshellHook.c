#include "utils.h"

__attribute__((constructor))
static void init()
{
	initErrorCodeMap();
	saveOriginalFunction();
}

// hooked library function
void perror (const char *message)
{
	reportError(message);
	INVOKE_ORIG_FUNC(perror)(message);
}

char * strerror (int errnum)
{
	return INVOKE_ORIG_FUNC(strerror)(errnum);
}

void error (int status, int errnum, const char *format, ...)
{
	int errnoBackup = errno;
	va_list args;
	va_start(args, format);
	error_varg(status, errnum, format, args);
	va_end(args);
	errno = errnoBackup;
}
