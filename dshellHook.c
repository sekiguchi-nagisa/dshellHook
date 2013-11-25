#include "utils.h"

__attribute__((constructor))
static void init()
{
	initErrorCodeMap();
	setErrorReportFileName( "DSHELL_ERROR_FILE");
	saveOriginalFunction();
}

void perror (const char *message)	// hook function
{
	INVOKE_ORIG_FUNC(perror)("");
}
