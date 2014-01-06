#include "utils.h"

int getpriority(int which, int who)
{
	int ret = CALL_ORIG_FUNC(getpriority)(which, who);
	if(ret == (int)-1) {
		reportError(errno, "getpriority");
	}
	return ret;
}

int setpriority(int which, int who, int prio)
{
	int ret = CALL_ORIG_FUNC(setpriority)(which, who, prio);
	if(ret == (int)-1) {
		reportError(errno, "setpriority");
	}
	return ret;
}
