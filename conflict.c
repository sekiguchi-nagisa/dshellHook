#include "utils.h"
#include <sys/types.h>

struct rlimit;
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

int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
	int ret = CALL_ORIG_FUNC(readlinkat)(dirfd, pathname, buf, bufsiz);
	if(ret == (int)-1) {
		reportError(errno, "readlinkat");
	}
	return ret;
}

struct mmsghdr;
struct timespec;
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout)
{
	int ret = CALL_ORIG_FUNC(recvmmsg)(sockfd, msgvec, vlen, flags, timeout);
	if(ret == (int)-1) {
		reportError(errno, "recvmmsg");
	}
	return ret;
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
{
	int ret = CALL_ORIG_FUNC(sendmmsg)(sockfd, msgvec, vlen, flags);
	if(ret == (int)-1) {
		reportError(errno, "sendmmsg");
	}
	return ret;
}

struct sembuf;
struct timespec;

int semop(int semid, struct sembuf *sops, unsigned nsops)
{
	int ret = CALL_ORIG_FUNC(semop)(semid, sops, nsops);
	if(ret == (int)-1) {
		reportError(errno, "semop");
	}
	return ret;
}

int semtimedop(int semid, struct sembuf *sops, unsigned nsops, struct timespec *timeout)
{
	int ret = CALL_ORIG_FUNC(semtimedop)(semid, sops, nsops, timeout);
	if(ret == (int)-1) {
		reportError(errno, "semtimedop");
	}
	return ret;
}


