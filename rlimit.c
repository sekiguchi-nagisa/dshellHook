#include "utils.h"
//#include <sys/time.h>
//#include <sys/resource.h>
#include <sys/types.h>

int getrlimit(int resource, struct rlimit *rlim)
{
	int ret = CALL_ORIG_FUNC(getrlimit)(resource, rlim);
	if(ret == (int)-1) {
		reportError(errno, "getrlimit");
	}
	return ret;
}

int setrlimit(int resource, const struct rlimit *rlim)
{
	int ret = CALL_ORIG_FUNC(setrlimit)(resource, rlim);
	if(ret == (int)-1) {
		reportError(errno, "setrlimit");
	}
	return ret;
}

int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
	int ret = CALL_ORIG_FUNC(prlimit)(pid, resource, new_limit, old_limit);
	if(ret == (int)-1) {
		reportError(errno, "prlimit");
	}
	return ret;
}
