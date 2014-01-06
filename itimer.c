#include "utils.h"

struct itimerval;
int getitimer(int which, struct itimerval *curr_value)
{
	int ret = CALL_ORIG_FUNC(getitimer)(which, curr_value);
	if(ret == (int)-1) {
		reportError(errno, "getitimer");
	}
	return ret;
}

int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
{
	int ret = CALL_ORIG_FUNC(setitimer)(which, new_value, old_value);
	if(ret == (int)-1) {
		reportError(errno, "setitimer");
	}
	return ret;
}
