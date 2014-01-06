#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <error.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "utils.h"

#define MAX_ERRNO 135
#define MAX_ERROR_CODE_SIZE 64
#define MAX_FILE_NAME 512

#define SET_ELEMENT(errnum) strncpy(errorCodeTable[errnum], #errnum, MAX_ERROR_CODE_SIZE)

static char *ereportEnv = "DSHELL_EREPORT";
static FuncIndex originalFuncSize = func_index_size;
static char errorCodeTable[MAX_ERRNO][MAX_ERROR_CODE_SIZE];
static char reportFileName[MAX_FILE_NAME];
static void **originalFuncTable;	// cannot change this name
// prototype
void saveFuncs(void **originalFuncTable);

static void reportLoadingError(char *funcname)
{
	fprintf(stderr, "%s\n", dlerror());
	char *msgPrefix = "dlsym failed: ";
	int msgSize = strlen(funcname) + strlen(msgPrefix) + 1;
	char newMsg[msgSize];
	// concat funcname to msgPrefix
	int i = 0, index = 0;
	while(msgPrefix[i] != '\0') {
		newMsg[index] = msgPrefix[i];
		i++;
		index++;
	}
	i = 0;
	while(funcname[i] != '\0') {
		newMsg[index] = funcname[i];
		i++;
		index++;
	}
	newMsg[index] = '\n';
	newMsg[++index]  = '\0';
	// invloke write syscall
	syscall(SYS_write, STDERR_FILENO, newMsg, msgSize);
}

void initErrorCodeMap()
{
	static int called = 0;
	if(called != 0) {
		return;
	}
	called = 1;
	strncpy(errorCodeTable[0], "SUCCESS", MAX_ERROR_CODE_SIZE);
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

static char *getErrorCodeString(int errorNum) {
	if(errorNum < 0 || errorNum > MAX_ERRNO) {
		fprintf(stderr, "invalid errno: %d\n", errorNum);
		_exit(1);
	}
	char *codeString = (char *)malloc(sizeof(char) * MAX_ERROR_CODE_SIZE);
	strncpy(codeString, errorCodeTable[errorNum], MAX_ERROR_CODE_SIZE);
	return codeString;
}

void *loadOriginalFuncion(char *funcname)
{
	void *funcp = dlsym(RTLD_NEXT, funcname);
//	if(funcp == NULL) {
//		reportLoadingError(funcname);
//		_exit(1);
//	}
	return funcp;
}

void saveOriginalFunction()
{
	char *envValue = getenv(ereportEnv);
	if(envValue == NULL) {
		fprintf(stderr, "empty env variable: %s\n", ereportEnv);
		_exit(1);
	}
	strncpy(reportFileName, envValue, MAX_FILE_NAME);
	originalFuncTable = (void **)malloc(sizeof(void *) * originalFuncSize);
	saveFuncs(originalFuncTable);
}

void reportError(int errnum, const char *syscallName)
{
	int errnoBackup = errno;
	FILE *fp = fopen(reportFileName, "a");
	if(fp == NULL) {
		fprintf(stderr, "error report file open faild: %s\n", reportFileName);
		_exit(1);
	}
	char *errorCode = getErrorCodeString(errnum);
	fprintf(fp, "%d::%s::%s::%s\n", getpid(), program_invocation_name, syscallName, errorCode);
	free(errorCode);
	fclose(fp);
	errno = errnoBackup;
}

void *getOriginalFunction(int index, char *funcname)
{
	void *funcp = originalFuncTable[index];
	if(funcp == NULL) {
		fprintf(stderr, "get original function faild: %s\n", funcname);
		_exit(1);
	}
	return funcp;
}

void error_varg(int status, int errnum, const char *format, va_list args)
{
	int bufferSize = 2048;
	char msgBuf[bufferSize];
	vsnprintf(msgBuf, bufferSize, format, args);
	reportError(errnum, "error");

	fprintf(stderr, "%s: ", program_invocation_name);
	fprintf(stderr, "%s", msgBuf);
	if(errnum != 0) {
		fprintf(stderr, ": %s", CALL_ORIG_FUNC(strerror)(errnum));
	}
	fprintf(stderr, "\n");
	if(status != 0) {
		exit(status);
	}
	error_message_count++;
}
