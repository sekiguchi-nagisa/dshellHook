#ifndef UTILS_H_
#define UTILS_H_

#define FUNC_INDEX(funcname) funcname ## _orig_index
#define FUNC_TYPE(funcname) funcname ## _orig_type

// function type
#define perror_orig_type (void (*)(const char*))


typedef enum {
	FUNC_INDEX(perror),
	max_index,
} FuncIndex;

#define INVOKE_ORIG_FUNC(funcname) (FUNC_TYPE(funcname)(getOriginalFunction(FUNC_INDEX(funcname))))


void initErrorCodeMap();
char *getErrorCodeString(int errorNum);
void setErrorReportFileName(char *envKey);
void saveOriginalFunction();
void *getOriginalFunction(FuncIndex index);

#endif /* UTILS_H_ */
