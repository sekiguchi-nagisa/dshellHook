#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include "utils.h"

#define MAX_ERRNO 135
#define MAX_ERROR_CODE_SIZE 64
#define MAX_FILE_NAME 512

#define SET_ELEMENT(errnum) strncpy(errorCodeTable[errnum], #errnum, MAX_ERROR_CODE_SIZE)
#define SAVE_FUNC(funcname) orignalFuncTable[FUNC_INDEX(funcname)] = dlsym(RTLD_NEXT, #funcname)

static FuncIndex orignalFuncSize = max_index;
static char errorCodeTable[MAX_ERRNO][MAX_ERROR_CODE_SIZE];
static char reportFileName[MAX_FILE_NAME];
static void **orignalFuncTable;	// cannot change this name

void initErrorCodeMap()
{
	static int called = 0;
	if(called != 0) {
		return;
	}
	called = 1;
	strcpy(errorCodeTable[0], "SUCCESS");
	SET_ELEMENT(EPERM            );
	SET_ELEMENT(ENOENT           );
	SET_ELEMENT(ESRCH            );
	SET_ELEMENT(EINTR            );
	SET_ELEMENT(EIO              );
	SET_ELEMENT(ENXIO            );
	SET_ELEMENT(E2BIG            );
	SET_ELEMENT(ENOEXEC          );
	SET_ELEMENT(EBADF            );
	SET_ELEMENT(ECHILD           );
	SET_ELEMENT(EAGAIN           );
	SET_ELEMENT(ENOMEM           );
	SET_ELEMENT(EACCES           );
	SET_ELEMENT(EFAULT           );
	SET_ELEMENT(ENOTBLK          );
	SET_ELEMENT(EBUSY            );
	SET_ELEMENT(EEXIST           );
	SET_ELEMENT(EXDEV            );
	SET_ELEMENT(ENODEV           );
	SET_ELEMENT(ENOTDIR          );
	SET_ELEMENT(EISDIR           );
	SET_ELEMENT(EINVAL           );
	SET_ELEMENT(ENFILE           );
	SET_ELEMENT(EMFILE           );
	SET_ELEMENT(ENOTTY           );
	SET_ELEMENT(ETXTBSY          );
	SET_ELEMENT(EFBIG            );
	SET_ELEMENT(ENOSPC           );
	SET_ELEMENT(ESPIPE           );
	SET_ELEMENT(EROFS            );
	SET_ELEMENT(EMLINK           );
	SET_ELEMENT(EPIPE            );
	SET_ELEMENT(EDOM             );
	SET_ELEMENT(ERANGE           );
	SET_ELEMENT(EDEADLK          );
	SET_ELEMENT(ENAMETOOLONG     );
	SET_ELEMENT(ENOLCK           );
	SET_ELEMENT(ENOSYS           );
	SET_ELEMENT(ENOTEMPTY        );
	SET_ELEMENT(ELOOP            );
	SET_ELEMENT(ENOMSG           );
	SET_ELEMENT(EIDRM            );
	SET_ELEMENT(ECHRNG           );
	SET_ELEMENT(EL2NSYNC         );
	SET_ELEMENT(EL3HLT           );
	SET_ELEMENT(EL3RST           );
	SET_ELEMENT(ELNRNG           );
	SET_ELEMENT(EUNATCH          );
	SET_ELEMENT(ENOCSI           );
	SET_ELEMENT(EL2HLT           );
	SET_ELEMENT(EBADE            );
	SET_ELEMENT(EBADR            );
	SET_ELEMENT(EXFULL           );
	SET_ELEMENT(ENOANO           );
	SET_ELEMENT(EBADRQC          );
	SET_ELEMENT(EBADSLT          );
	SET_ELEMENT(EBFONT           );
	SET_ELEMENT(ENOSTR           );
	SET_ELEMENT(ENODATA          );
	SET_ELEMENT(ETIME            );
	SET_ELEMENT(ENOSR            );
	SET_ELEMENT(ENONET           );
	SET_ELEMENT(ENOPKG           );
	SET_ELEMENT(EREMOTE          );
	SET_ELEMENT(ENOLINK          );
	SET_ELEMENT(EADV             );
	SET_ELEMENT(ESRMNT           );
	SET_ELEMENT(ECOMM            );
	SET_ELEMENT(EPROTO           );
	SET_ELEMENT(EMULTIHOP        );
	SET_ELEMENT(EDOTDOT          );
	SET_ELEMENT(EBADMSG          );
	SET_ELEMENT(EOVERFLOW        );
	SET_ELEMENT(ENOTUNIQ         );
	SET_ELEMENT(EBADFD           );
	SET_ELEMENT(EREMCHG          );
	SET_ELEMENT(ELIBACC          );
	SET_ELEMENT(ELIBBAD          );
	SET_ELEMENT(ELIBSCN          );
	SET_ELEMENT(ELIBMAX          );
	SET_ELEMENT(ELIBEXEC         );
	SET_ELEMENT(EILSEQ           );
	SET_ELEMENT(ERESTART         );
	SET_ELEMENT(ESTRPIPE         );
	SET_ELEMENT(EUSERS           );
	SET_ELEMENT(ENOTSOCK         );
	SET_ELEMENT(EDESTADDRREQ     );
	SET_ELEMENT(EMSGSIZE         );
	SET_ELEMENT(EPROTOTYPE       );
	SET_ELEMENT(ENOPROTOOPT      );
	SET_ELEMENT(EPROTONOSUPPORT  );
	SET_ELEMENT(ESOCKTNOSUPPORT  );
	SET_ELEMENT(EOPNOTSUPP       );
	SET_ELEMENT(EPFNOSUPPORT     );
	SET_ELEMENT(EAFNOSUPPORT     );
	SET_ELEMENT(EADDRINUSE       );
	SET_ELEMENT(EADDRNOTAVAIL    );
	SET_ELEMENT(ENETDOWN         );
	SET_ELEMENT(ENETUNREACH      );
	SET_ELEMENT(ENETRESET        );
	SET_ELEMENT(ECONNABORTED     );
	SET_ELEMENT(ECONNRESET       );
	SET_ELEMENT(ENOBUFS          );
	SET_ELEMENT(EISCONN          );
	SET_ELEMENT(ENOTCONN         );
	SET_ELEMENT(ESHUTDOWN        );
	SET_ELEMENT(ETOOMANYREFS     );
	SET_ELEMENT(ETIMEDOUT        );
	SET_ELEMENT(ECONNREFUSED     );
	SET_ELEMENT(EHOSTDOWN        );
	SET_ELEMENT(EHOSTUNREACH     );
	SET_ELEMENT(EALREADY         );
	SET_ELEMENT(EINPROGRESS      );
	SET_ELEMENT(ESTALE           );
	SET_ELEMENT(EUCLEAN          );
	SET_ELEMENT(ENOTNAM          );
	SET_ELEMENT(ENAVAIL          );
	SET_ELEMENT(EISNAM           );
	SET_ELEMENT(EREMOTEIO        );
	SET_ELEMENT(EDQUOT           );
	SET_ELEMENT(ENOMEDIUM        );
	SET_ELEMENT(EMEDIUMTYPE      );
	SET_ELEMENT(ECANCELED        );
	SET_ELEMENT(ENOKEY           );
	SET_ELEMENT(EKEYEXPIRED      );
	SET_ELEMENT(EKEYREVOKED      );
	SET_ELEMENT(EKEYREJECTED     );
	SET_ELEMENT(EOWNERDEAD       );
	SET_ELEMENT(ENOTRECOVERABLE  );
	SET_ELEMENT(ERFKILL          );
	SET_ELEMENT(EHWPOISON        );
}

char *getErrorCodeString(int errorNum) {
	if(errorNum < 0 || errorNum > MAX_ERRNO) {
		fprintf(stderr, "invalid errno: %d", errorNum);
		return NULL;
	}
	char *codeString = (char *)malloc(sizeof(char) * MAX_ERROR_CODE_SIZE);
	strncpy(codeString, errorCodeTable[errorNum], MAX_ERROR_CODE_SIZE);
	return codeString;
}

void setErrorReportFileName(char *envKey)
{
	strncpy(reportFileName, getenv(envKey), MAX_FILE_NAME);
}

void saveOriginalFunction()
{
	orignalFuncTable = (void **)malloc(sizeof(void *) * orignalFuncSize);
	SAVE_FUNC(perror);
}

void reportError(int errorCode)
{
	FILE *fp = fopen(reportFileName, "a");
	if(fp == NULL) {
		fprintf(stderr, "error report file open faild: %s\n", reportFileName);
		exit(1);
	}
}

void *getOriginalFunction(FuncIndex index)
{
	return orignalFuncTable[index];
}
