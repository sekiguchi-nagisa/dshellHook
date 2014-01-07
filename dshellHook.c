#include "utils.h"
#include "autogensrc/headerList.h"

// hooked library function
void perror (const char *message)
{
	reportError(errno, "perror");
	CALL_ORIG_FUNC(perror)(message);
}

char * strerror (int errnum)
{
	reportError(errnum, "strerror");
	return CALL_ORIG_FUNC(strerror)(errnum);
}

char * strerror_r (int errnum, char *buf, size_t n)
{
	reportError(errnum, "strerror_r");
	return CALL_ORIG_FUNC(strerror_r)(errnum, buf, n);
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

// stub function
void exit(int status)
{
	reportError(0, "exit");
	CALL_ORIG_FUNC(exit)(status);
}

//<Head> !!auto generated function wrapper. do not change this comment
// example
void * mmap(void *address, size_t length, int protect, int flags, int filedes, off_t offset)
{
	void * ret = CALL_ORIG_FUNC(mmap)(address, length, protect, flags, filedes, offset);
	if(ret == (void *)-1) {
		reportError(errno, "mmap");
	}
	return ret;
}

void * mmap64(void *address, size_t length, int protect, int flags, int filedes, off64_t offset)
{
	void * ret = CALL_ORIG_FUNC(mmap64)(address, length, protect, flags, filedes, offset);
	if(ret == (void *)-1) {
		reportError(errno, "mmap64");
	}
	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = CALL_ORIG_FUNC(accept)(sockfd, addr, addrlen);
	if(ret == (int)-1) {
		reportError(errno, "accept");
	}
	return ret;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int ret = CALL_ORIG_FUNC(accept4)(sockfd, addr, addrlen, flags);
	if(ret == (int)-1) {
		reportError(errno, "accept4");
	}
	return ret;
}

int access(const char *pathname, int mode)
{
	int ret = CALL_ORIG_FUNC(access)(pathname, mode);
	if(ret == (int)-1) {
		reportError(errno, "access");
	}
	return ret;
}

int acct(const char *filename)
{
	int ret = CALL_ORIG_FUNC(acct)(filename);
	if(ret == (int)-1) {
		reportError(errno, "acct");
	}
	return ret;
}

key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
	key_serial_t ret = CALL_ORIG_FUNC(add_key)(type, description, payload, plen, keyring);
	if(ret == (key_serial_t)-1) {
		reportError(errno, "add_key");
	}
	return ret;
}

int adjtimex(struct timex *buf)
{
	int ret = CALL_ORIG_FUNC(adjtimex)(buf);
	if(ret == (int)-1) {
		reportError(errno, "adjtimex");
	}
	return ret;
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	int ret = CALL_ORIG_FUNC(posix_fadvise)(fd, offset, len, advice);
	if(ret == (int)-1) {
		reportError(errno, "posix_fadvise");
	}
	return ret;
}

int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
	int ret = CALL_ORIG_FUNC(sync_file_range)(fd, offset, nbytes, flags);
	if(ret == (int)-1) {
		reportError(errno, "sync_file_range");
	}
	return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret = CALL_ORIG_FUNC(bind)(sockfd, addr, addrlen);
	if(ret == (int)-1) {
		reportError(errno, "bind");
	}
	return ret;
}

int brk(void *addr)
{
	int ret = CALL_ORIG_FUNC(brk)(addr);
	if(ret == (int)-1) {
		reportError(errno, "brk");
	}
	return ret;
}

void * sbrk(intptr_t increment)
{
	void * ret = CALL_ORIG_FUNC(sbrk)(increment);
	if(ret == (void *)-1) {
		reportError(errno, "sbrk");
	}
	return ret;
}

int capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	int ret = CALL_ORIG_FUNC(capget)(hdrp, datap);
	if(ret == (int)-1) {
		reportError(errno, "capget");
	}
	return ret;
}

int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	int ret = CALL_ORIG_FUNC(capset)(hdrp, datap);
	if(ret == (int)-1) {
		reportError(errno, "capset");
	}
	return ret;
}

int chdir(const char *path)
{
	int ret = CALL_ORIG_FUNC(chdir)(path);
	if(ret == (int)-1) {
		reportError(errno, "chdir");
	}
	return ret;
}

int fchdir(int fd)
{
	int ret = CALL_ORIG_FUNC(fchdir)(fd);
	if(ret == (int)-1) {
		reportError(errno, "fchdir");
	}
	return ret;
}

int chmod(const char *path, mode_t mode)
{
	int ret = CALL_ORIG_FUNC(chmod)(path, mode);
	if(ret == (int)-1) {
		reportError(errno, "chmod");
	}
	return ret;
}

int fchmod(int fd, mode_t mode)
{
	int ret = CALL_ORIG_FUNC(fchmod)(fd, mode);
	if(ret == (int)-1) {
		reportError(errno, "fchmod");
	}
	return ret;
}

int chown(const char *path, uid_t owner, gid_t group)
{
	int ret = CALL_ORIG_FUNC(chown)(path, owner, group);
	if(ret == (int)-1) {
		reportError(errno, "chown");
	}
	return ret;
}

int fchown(int fd, uid_t owner, gid_t group)
{
	int ret = CALL_ORIG_FUNC(fchown)(fd, owner, group);
	if(ret == (int)-1) {
		reportError(errno, "fchown");
	}
	return ret;
}

int lchown(const char *path, uid_t owner, gid_t group)
{
	int ret = CALL_ORIG_FUNC(lchown)(path, owner, group);
	if(ret == (int)-1) {
		reportError(errno, "lchown");
	}
	return ret;
}

int chroot(const char *path)
{
	int ret = CALL_ORIG_FUNC(chroot)(path);
	if(ret == (int)-1) {
		reportError(errno, "chroot");
	}
	return ret;
}

int clock_getres(clockid_t clk_id, struct timespec *res)
{
	int ret = CALL_ORIG_FUNC(clock_getres)(clk_id, res);
	if(ret == (int)-1) {
		reportError(errno, "clock_getres");
	}
	return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	int ret = CALL_ORIG_FUNC(clock_gettime)(clk_id, tp);
	if(ret == (int)-1) {
		reportError(errno, "clock_gettime");
	}
	return ret;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp)
{
	int ret = CALL_ORIG_FUNC(clock_settime)(clk_id, tp);
	if(ret == (int)-1) {
		reportError(errno, "clock_settime");
	}
	return ret;
}

int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remain)
{
	int ret = CALL_ORIG_FUNC(clock_nanosleep)(clock_id, flags, request, remain);
	if(ret == (int)-1) {
		reportError(errno, "clock_nanosleep");
	}
	return ret;
}

int close(int fd)
{
	int ret = CALL_ORIG_FUNC(close)(fd);
	if(ret == (int)-1) {
		reportError(errno, "close");
	}
	return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret = CALL_ORIG_FUNC(connect)(sockfd, addr, addrlen);
	if(ret == (int)-1) {
		reportError(errno, "connect");
	}
	return ret;
}

int creat(const char *pathname, mode_t mode)
{
	int ret = CALL_ORIG_FUNC(creat)(pathname, mode);
	if(ret == (int)-1) {
		reportError(errno, "creat");
	}
	return ret;
}

int dup(int oldfd)
{
	int ret = CALL_ORIG_FUNC(dup)(oldfd);
	if(ret == (int)-1) {
		reportError(errno, "dup");
	}
	return ret;
}

int dup2(int oldfd, int newfd)
{
	int ret = CALL_ORIG_FUNC(dup2)(oldfd, newfd);
	if(ret == (int)-1) {
		reportError(errno, "dup2");
	}
	return ret;
}

int dup3(int oldfd, int newfd, int flags)
{
	int ret = CALL_ORIG_FUNC(dup3)(oldfd, newfd, flags);
	if(ret == (int)-1) {
		reportError(errno, "dup3");
	}
	return ret;
}

int epoll_create(int size)
{
	int ret = CALL_ORIG_FUNC(epoll_create)(size);
	if(ret == (int)-1) {
		reportError(errno, "epoll_create");
	}
	return ret;
}

int epoll_create1(int flags)
{
	int ret = CALL_ORIG_FUNC(epoll_create1)(flags);
	if(ret == (int)-1) {
		reportError(errno, "epoll_create1");
	}
	return ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	int ret = CALL_ORIG_FUNC(epoll_ctl)(epfd, op, fd, event);
	if(ret == (int)-1) {
		reportError(errno, "epoll_ctl");
	}
	return ret;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	int ret = CALL_ORIG_FUNC(epoll_wait)(epfd, events, maxevents, timeout);
	if(ret == (int)-1) {
		reportError(errno, "epoll_wait");
	}
	return ret;
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)
{
	int ret = CALL_ORIG_FUNC(epoll_pwait)(epfd, events, maxevents, timeout, sigmask);
	if(ret == (int)-1) {
		reportError(errno, "epoll_pwait");
	}
	return ret;
}

int eventfd(unsigned int initval, int flags)
{
	int ret = CALL_ORIG_FUNC(eventfd)(initval, flags);
	if(ret == (int)-1) {
		reportError(errno, "eventfd");
	}
	return ret;
}

int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
	int ret = CALL_ORIG_FUNC(faccessat)(dirfd, pathname, mode, flags);
	if(ret == (int)-1) {
		reportError(errno, "faccessat");
	}
	return ret;
}

int fallocate(int fd, int mode, off_t offset, off_t len)
{
	int ret = CALL_ORIG_FUNC(fallocate)(fd, mode, offset, len);
	if(ret == (int)-1) {
		reportError(errno, "fallocate");
	}
	return ret;
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	int ret = CALL_ORIG_FUNC(fchmodat)(dirfd, pathname, mode, flags);
	if(ret == (int)-1) {
		reportError(errno, "fchmodat");
	}
	return ret;
}

int fsync(int fd)
{
	int ret = CALL_ORIG_FUNC(fsync)(fd);
	if(ret == (int)-1) {
		reportError(errno, "fsync");
	}
	return ret;
}

int fdatasync(int fd)
{
	int ret = CALL_ORIG_FUNC(fdatasync)(fd);
	if(ret == (int)-1) {
		reportError(errno, "fdatasync");
	}
	return ret;
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size)
{
	ssize_t ret = CALL_ORIG_FUNC(getxattr)(path, name, value, size);
	if(ret == (ssize_t)-1) {
		reportError(errno, "getxattr");
	}
	return ret;
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)
{
	ssize_t ret = CALL_ORIG_FUNC(lgetxattr)(path, name, value, size);
	if(ret == (ssize_t)-1) {
		reportError(errno, "lgetxattr");
	}
	return ret;
}

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)
{
	ssize_t ret = CALL_ORIG_FUNC(fgetxattr)(fd, name, value, size);
	if(ret == (ssize_t)-1) {
		reportError(errno, "fgetxattr");
	}
	return ret;
}

int flock(int fd, int operation)
{
	int ret = CALL_ORIG_FUNC(flock)(fd, operation);
	if(ret == (int)-1) {
		reportError(errno, "flock");
	}
	return ret;
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	int ret = CALL_ORIG_FUNC(setxattr)(path, name, value, size, flags);
	if(ret == (int)-1) {
		reportError(errno, "setxattr");
	}
	return ret;
}

int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
	int ret = CALL_ORIG_FUNC(lsetxattr)(path, name, value, size, flags);
	if(ret == (int)-1) {
		reportError(errno, "lsetxattr");
	}
	return ret;
}

int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
	int ret = CALL_ORIG_FUNC(fsetxattr)(fd, name, value, size, flags);
	if(ret == (int)-1) {
		reportError(errno, "fsetxattr");
	}
	return ret;
}

int stat(const char *path, struct stat *buf)
{
	int ret = CALL_ORIG_FUNC(stat)(path, buf);
	if(ret == (int)-1) {
		reportError(errno, "stat");
	}
	return ret;
}

int fstat(int fd, struct stat *buf)
{
	int ret = CALL_ORIG_FUNC(fstat)(fd, buf);
	if(ret == (int)-1) {
		reportError(errno, "fstat");
	}
	return ret;
}

int lstat(const char *path, struct stat *buf)
{
	int ret = CALL_ORIG_FUNC(lstat)(path, buf);
	if(ret == (int)-1) {
		reportError(errno, "lstat");
	}
	return ret;
}

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
	int ret = CALL_ORIG_FUNC(fstatat)(dirfd, pathname, buf, flags);
	if(ret == (int)-1) {
		reportError(errno, "fstatat");
	}
	return ret;
}

int statfs(const char *path, struct statfs *buf)
{
	int ret = CALL_ORIG_FUNC(statfs)(path, buf);
	if(ret == (int)-1) {
		reportError(errno, "statfs");
	}
	return ret;
}

int fstatfs(int fd, struct statfs *buf)
{
	int ret = CALL_ORIG_FUNC(fstatfs)(fd, buf);
	if(ret == (int)-1) {
		reportError(errno, "fstatfs");
	}
	return ret;
}

int statvfs(const char *path, struct statvfs *buf)
{
	int ret = CALL_ORIG_FUNC(statvfs)(path, buf);
	if(ret == (int)-1) {
		reportError(errno, "statvfs");
	}
	return ret;
}

int fstatvfs(int fd, struct statvfs *buf)
{
	int ret = CALL_ORIG_FUNC(fstatvfs)(fd, buf);
	if(ret == (int)-1) {
		reportError(errno, "fstatvfs");
	}
	return ret;
}

int truncate(const char *path, off_t length)
{
	int ret = CALL_ORIG_FUNC(truncate)(path, length);
	if(ret == (int)-1) {
		reportError(errno, "truncate");
	}
	return ret;
}

int ftruncate(int fd, off_t length)
{
	int ret = CALL_ORIG_FUNC(ftruncate)(fd, length);
	if(ret == (int)-1) {
		reportError(errno, "ftruncate");
	}
	return ret;
}

int futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
	int ret = CALL_ORIG_FUNC(futex)(uaddr, op, val, timeout, uaddr2, val3);
	if(ret == (int)-1) {
		reportError(errno, "futex");
	}
	return ret;
}

char * getcwd(char *buf, size_t size)
{
	char * ret = CALL_ORIG_FUNC(getcwd)(buf, size);
	if(ret == (char *)-1) {
		reportError(errno, "getcwd");
	}
	return ret;
}

char * getwd(char *buf)
{
	char * ret = CALL_ORIG_FUNC(getwd)(buf);
	if(ret == (char *)-1) {
		reportError(errno, "getwd");
	}
	return ret;
}

char * get_current_dir_name(void)
{
	char * ret = CALL_ORIG_FUNC(get_current_dir_name)();
	if(ret == (char *)-1) {
		reportError(errno, "get_current_dir_name");
	}
	return ret;
}

int getdomainname(char *name, size_t len)
{
	int ret = CALL_ORIG_FUNC(getdomainname)(name, len);
	if(ret == (int)-1) {
		reportError(errno, "getdomainname");
	}
	return ret;
}

int setdomainname(const char *name, size_t len)
{
	int ret = CALL_ORIG_FUNC(setdomainname)(name, len);
	if(ret == (int)-1) {
		reportError(errno, "setdomainname");
	}
	return ret;
}

int getdtablesize(void)
{
	int ret = CALL_ORIG_FUNC(getdtablesize)();
	if(ret == (int)-1) {
		reportError(errno, "getdtablesize");
	}
	return ret;
}

int setgroups(size_t size, const gid_t *list)
{
	int ret = CALL_ORIG_FUNC(setgroups)(size, list);
	if(ret == (int)-1) {
		reportError(errno, "setgroups");
	}
	return ret;
}

long gethostid(void)
{
	long ret = CALL_ORIG_FUNC(gethostid)();
	if(ret == (long)-1) {
		reportError(errno, "gethostid");
	}
	return ret;
}

int sethostid(long hostid)
{
	int ret = CALL_ORIG_FUNC(sethostid)(hostid);
	if(ret == (int)-1) {
		reportError(errno, "sethostid");
	}
	return ret;
}

int gethostname(char *name, size_t len)
{
	int ret = CALL_ORIG_FUNC(gethostname)(name, len);
	if(ret == (int)-1) {
		reportError(errno, "gethostname");
	}
	return ret;
}

int sethostname(const char *name, size_t len)
{
	int ret = CALL_ORIG_FUNC(sethostname)(name, len);
	if(ret == (int)-1) {
		reportError(errno, "sethostname");
	}
	return ret;
}

int get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
	int ret = CALL_ORIG_FUNC(get_mempolicy)(mode, nodemask, maxnode, addr, flags);
	if(ret == (int)-1) {
		reportError(errno, "get_mempolicy");
	}
	return ret;
}

int getpagesize(void)
{
	int ret = CALL_ORIG_FUNC(getpagesize)();
	if(ret == (int)-1) {
		reportError(errno, "getpagesize");
	}
	return ret;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = CALL_ORIG_FUNC(getpeername)(sockfd, addr, addrlen);
	if(ret == (int)-1) {
		reportError(errno, "getpeername");
	}
	return ret;
}

int setpgid(pid_t pid, pid_t pgid)
{
	int ret = CALL_ORIG_FUNC(setpgid)(pid, pgid);
	if(ret == (int)-1) {
		reportError(errno, "setpgid");
	}
	return ret;
}

pid_t getpgid(pid_t pid)
{
	pid_t ret = CALL_ORIG_FUNC(getpgid)(pid);
	if(ret == (pid_t)-1) {
		reportError(errno, "getpgid");
	}
	return ret;
}

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	int ret = CALL_ORIG_FUNC(getresuid)(ruid, euid, suid);
	if(ret == (int)-1) {
		reportError(errno, "getresuid");
	}
	return ret;
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	int ret = CALL_ORIG_FUNC(getresgid)(rgid, egid, sgid);
	if(ret == (int)-1) {
		reportError(errno, "getresgid");
	}
	return ret;
}

int getrusage(int who, struct rusage *usage)
{
	int ret = CALL_ORIG_FUNC(getrusage)(who, usage);
	if(ret == (int)-1) {
		reportError(errno, "getrusage");
	}
	return ret;
}

pid_t getsid(pid_t pid)
{
	pid_t ret = CALL_ORIG_FUNC(getsid)(pid);
	if(ret == (pid_t)-1) {
		reportError(errno, "getsid");
	}
	return ret;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = CALL_ORIG_FUNC(getsockname)(sockfd, addr, addrlen);
	if(ret == (int)-1) {
		reportError(errno, "getsockname");
	}
	return ret;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	int ret = CALL_ORIG_FUNC(getsockopt)(sockfd, level, optname, optval, optlen);
	if(ret == (int)-1) {
		reportError(errno, "getsockopt");
	}
	return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	int ret = CALL_ORIG_FUNC(setsockopt)(sockfd, level, optname, optval, optlen);
	if(ret == (int)-1) {
		reportError(errno, "setsockopt");
	}
	return ret;
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	int ret = CALL_ORIG_FUNC(gettimeofday)(tv, tz);
	if(ret == (int)-1) {
		reportError(errno, "gettimeofday");
	}
	return ret;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
	int ret = CALL_ORIG_FUNC(settimeofday)(tv, tz);
	if(ret == (int)-1) {
		reportError(errno, "settimeofday");
	}
	return ret;
}

int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
	int ret = CALL_ORIG_FUNC(inotify_add_watch)(fd, pathname, mask);
	if(ret == (int)-1) {
		reportError(errno, "inotify_add_watch");
	}
	return ret;
}

int inotify_init(void)
{
	int ret = CALL_ORIG_FUNC(inotify_init)();
	if(ret == (int)-1) {
		reportError(errno, "inotify_init");
	}
	return ret;
}

int inotify_init1(int flags)
{
	int ret = CALL_ORIG_FUNC(inotify_init1)(flags);
	if(ret == (int)-1) {
		reportError(errno, "inotify_init1");
	}
	return ret;
}

int inotify_rm_watch(int fd, int wd)
{
	int ret = CALL_ORIG_FUNC(inotify_rm_watch)(fd, wd);
	if(ret == (int)-1) {
		reportError(errno, "inotify_rm_watch");
	}
	return ret;
}

int ioperm(unsigned long from, unsigned long num, int turn_on)
{
	int ret = CALL_ORIG_FUNC(ioperm)(from, num, turn_on);
	if(ret == (int)-1) {
		reportError(errno, "ioperm");
	}
	return ret;
}

int iopl(int level)
{
	int ret = CALL_ORIG_FUNC(iopl)(level);
	if(ret == (int)-1) {
		reportError(errno, "iopl");
	}
	return ret;
}

int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth)
{
	int ret = CALL_ORIG_FUNC(ipc)(call, first, second, third, ptr, fifth);
	if(ret == (int)-1) {
		reportError(errno, "ipc");
	}
	return ret;
}

int kill(pid_t pid, int sig)
{
	int ret = CALL_ORIG_FUNC(kill)(pid, sig);
	if(ret == (int)-1) {
		reportError(errno, "kill");
	}
	return ret;
}

int killpg(int pgrp, int sig)
{
	int ret = CALL_ORIG_FUNC(killpg)(pgrp, sig);
	if(ret == (int)-1) {
		reportError(errno, "killpg");
	}
	return ret;
}

int link(const char *oldpath, const char *newpath)
{
	int ret = CALL_ORIG_FUNC(link)(oldpath, newpath);
	if(ret == (int)-1) {
		reportError(errno, "link");
	}
	return ret;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
	int ret = CALL_ORIG_FUNC(linkat)(olddirfd, oldpath, newdirfd, newpath, flags);
	if(ret == (int)-1) {
		reportError(errno, "linkat");
	}
	return ret;
}

int listen(int sockfd, int backlog)
{
	int ret = CALL_ORIG_FUNC(listen)(sockfd, backlog);
	if(ret == (int)-1) {
		reportError(errno, "listen");
	}
	return ret;
}

size_t listxattr(const char *path, char *list, size_t size)
{
	size_t ret = CALL_ORIG_FUNC(listxattr)(path, list, size);
	if(ret == (size_t)-1) {
		reportError(errno, "listxattr");
	}
	return ret;
}

ssize_t llistxattr(const char *path, char *list, size_t size)
{
	ssize_t ret = CALL_ORIG_FUNC(llistxattr)(path, list, size);
	if(ret == (ssize_t)-1) {
		reportError(errno, "llistxattr");
	}
	return ret;
}

ssize_t flistxattr(int fd, char *list, size_t size)
{
	ssize_t ret = CALL_ORIG_FUNC(flistxattr)(fd, list, size);
	if(ret == (ssize_t)-1) {
		reportError(errno, "flistxattr");
	}
	return ret;
}

int removexattr(const char *path, const char *name)
{
	int ret = CALL_ORIG_FUNC(removexattr)(path, name);
	if(ret == (int)-1) {
		reportError(errno, "removexattr");
	}
	return ret;
}

int lremovexattr(const char *path, const char *name)
{
	int ret = CALL_ORIG_FUNC(lremovexattr)(path, name);
	if(ret == (int)-1) {
		reportError(errno, "lremovexattr");
	}
	return ret;
}

int fremovexattr(int fd, const char *name)
{
	int ret = CALL_ORIG_FUNC(fremovexattr)(fd, name);
	if(ret == (int)-1) {
		reportError(errno, "fremovexattr");
	}
	return ret;
}

off_t lseek(int fd, off_t offset, int whence)
{
	off_t ret = CALL_ORIG_FUNC(lseek)(fd, offset, whence);
	if(ret == (off_t)-1) {
		reportError(errno, "lseek");
	}
	return ret;
}

int madvise(void *addr, size_t length, int advice)
{
	int ret = CALL_ORIG_FUNC(madvise)(addr, length, advice);
	if(ret == (int)-1) {
		reportError(errno, "madvise");
	}
	return ret;
}

int mbind(void *addr, unsigned long len, int mode, unsigned long *nodemask, unsigned long maxnode, unsigned flags)
{
	int ret = CALL_ORIG_FUNC(mbind)(addr, len, mode, nodemask, maxnode, flags);
	if(ret == (int)-1) {
		reportError(errno, "mbind");
	}
	return ret;
}

long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes)
{
	long ret = CALL_ORIG_FUNC(migrate_pages)(pid, maxnode, old_nodes, new_nodes);
	if(ret == (long)-1) {
		reportError(errno, "migrate_pages");
	}
	return ret;
}

int mincore(void *addr, size_t length, unsigned char *vec)
{
	int ret = CALL_ORIG_FUNC(mincore)(addr, length, vec);
	if(ret == (int)-1) {
		reportError(errno, "mincore");
	}
	return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
	int ret = CALL_ORIG_FUNC(mkdir)(pathname, mode);
	if(ret == (int)-1) {
		reportError(errno, "mkdir");
	}
	return ret;
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	int ret = CALL_ORIG_FUNC(mkdirat)(dirfd, pathname, mode);
	if(ret == (int)-1) {
		reportError(errno, "mkdirat");
	}
	return ret;
}

int mknod(const char *pathname, mode_t mode, dev_t dev)
{
	int ret = CALL_ORIG_FUNC(mknod)(pathname, mode, dev);
	if(ret == (int)-1) {
		reportError(errno, "mknod");
	}
	return ret;
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
	int ret = CALL_ORIG_FUNC(mknodat)(dirfd, pathname, mode, dev);
	if(ret == (int)-1) {
		reportError(errno, "mknodat");
	}
	return ret;
}

int mlock(const void *addr, size_t len)
{
	int ret = CALL_ORIG_FUNC(mlock)(addr, len);
	if(ret == (int)-1) {
		reportError(errno, "mlock");
	}
	return ret;
}

int munlock(const void *addr, size_t len)
{
	int ret = CALL_ORIG_FUNC(munlock)(addr, len);
	if(ret == (int)-1) {
		reportError(errno, "munlock");
	}
	return ret;
}

int mlockall(int flags)
{
	int ret = CALL_ORIG_FUNC(mlockall)(flags);
	if(ret == (int)-1) {
		reportError(errno, "mlockall");
	}
	return ret;
}

int munlockall(void)
{
	int ret = CALL_ORIG_FUNC(munlockall)();
	if(ret == (int)-1) {
		reportError(errno, "munlockall");
	}
	return ret;
}

int munmap(void *addr, size_t length)
{
	int ret = CALL_ORIG_FUNC(munmap)(addr, length);
	if(ret == (int)-1) {
		reportError(errno, "munmap");
	}
	return ret;
}

void * mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset)
{
	void * ret = CALL_ORIG_FUNC(mmap2)(addr, length, prot, flags, fd, pgoffset);
	if(ret == (void *)-1) {
		reportError(errno, "mmap2");
	}
	return ret;
}

int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
	int ret = CALL_ORIG_FUNC(mount)(source, target, filesystemtype, mountflags, data);
	if(ret == (int)-1) {
		reportError(errno, "mount");
	}
	return ret;
}

int mprotect(void *addr, size_t len, int prot)
{
	int ret = CALL_ORIG_FUNC(mprotect)(addr, len, prot);
	if(ret == (int)-1) {
		reportError(errno, "mprotect");
	}
	return ret;
}

int mq_notify(mqd_t mqdes, const struct sigevent *sevp)
{
	int ret = CALL_ORIG_FUNC(mq_notify)(mqdes, sevp);
	if(ret == (int)-1) {
		reportError(errno, "mq_notify");
	}
	return ret;
}

ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio)
{
	ssize_t ret = CALL_ORIG_FUNC(mq_receive)(mqdes, msg_ptr, msg_len, msg_prio);
	if(ret == (ssize_t)-1) {
		reportError(errno, "mq_receive");
	}
	return ret;
}

ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio, const struct timespec *abs_timeout)
{
	ssize_t ret = CALL_ORIG_FUNC(mq_timedreceive)(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	if(ret == (ssize_t)-1) {
		reportError(errno, "mq_timedreceive");
	}
	return ret;
}

int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio)
{
	int ret = CALL_ORIG_FUNC(mq_send)(mqdes, msg_ptr, msg_len, msg_prio);
	if(ret == (int)-1) {
		reportError(errno, "mq_send");
	}
	return ret;
}

int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio, const struct timespec *abs_timeout)
{
	int ret = CALL_ORIG_FUNC(mq_timedsend)(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	if(ret == (int)-1) {
		reportError(errno, "mq_timedsend");
	}
	return ret;
}

int mq_unlink(const char *name)
{
	int ret = CALL_ORIG_FUNC(mq_unlink)(name);
	if(ret == (int)-1) {
		reportError(errno, "mq_unlink");
	}
	return ret;
}

int msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
	int ret = CALL_ORIG_FUNC(msgctl)(msqid, cmd, buf);
	if(ret == (int)-1) {
		reportError(errno, "msgctl");
	}
	return ret;
}

int msgget(key_t key, int msgflg)
{
	int ret = CALL_ORIG_FUNC(msgget)(key, msgflg);
	if(ret == (int)-1) {
		reportError(errno, "msgget");
	}
	return ret;
}

int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	int ret = CALL_ORIG_FUNC(msgsnd)(msqid, msgp, msgsz, msgflg);
	if(ret == (int)-1) {
		reportError(errno, "msgsnd");
	}
	return ret;
}

ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	ssize_t ret = CALL_ORIG_FUNC(msgrcv)(msqid, msgp, msgsz, msgtyp, msgflg);
	if(ret == (ssize_t)-1) {
		reportError(errno, "msgrcv");
	}
	return ret;
}

int msync(void *addr, size_t length, int flags)
{
	int ret = CALL_ORIG_FUNC(msync)(addr, length, flags);
	if(ret == (int)-1) {
		reportError(errno, "msync");
	}
	return ret;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	int ret = CALL_ORIG_FUNC(nanosleep)(req, rem);
	if(ret == (int)-1) {
		reportError(errno, "nanosleep");
	}
	return ret;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	int ret = CALL_ORIG_FUNC(select)(nfds, readfds, writefds, exceptfds, timeout);
	if(ret == (int)-1) {
		reportError(errno, "select");
	}
	return ret;
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)
{
	int ret = CALL_ORIG_FUNC(pselect)(nfds, readfds, writefds, exceptfds, timeout, sigmask);
	if(ret == (int)-1) {
		reportError(errno, "pselect");
	}
	return ret;
}

int nice(int inc)
{
	int ret = CALL_ORIG_FUNC(nice)(inc);
	if(ret == (int)-1) {
		reportError(errno, "nice");
	}
	return ret;
}

int uname(struct utsname *buf)
{
	int ret = CALL_ORIG_FUNC(uname)(buf);
	if(ret == (int)-1) {
		reportError(errno, "uname");
	}
	return ret;
}

int pause(void)
{
	int ret = CALL_ORIG_FUNC(pause)();
	if(ret == (int)-1) {
		reportError(errno, "pause");
	}
	return ret;
}

int pciconfig_read(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf)
{
	int ret = CALL_ORIG_FUNC(pciconfig_read)(bus, dfn, off, len, buf);
	if(ret == (int)-1) {
		reportError(errno, "pciconfig_read");
	}
	return ret;
}

int pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf)
{
	int ret = CALL_ORIG_FUNC(pciconfig_write)(bus, dfn, off, len, buf);
	if(ret == (int)-1) {
		reportError(errno, "pciconfig_write");
	}
	return ret;
}

int pciconfig_iobase(long which, unsigned long bus, unsigned long devfn)
{
	int ret = CALL_ORIG_FUNC(pciconfig_iobase)(which, bus, devfn);
	if(ret == (int)-1) {
		reportError(errno, "pciconfig_iobase");
	}
	return ret;
}

int personality(unsigned long persona)
{
	int ret = CALL_ORIG_FUNC(personality)(persona);
	if(ret == (int)-1) {
		reportError(errno, "personality");
	}
	return ret;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int ret = CALL_ORIG_FUNC(poll)(fds, nfds, timeout);
	if(ret == (int)-1) {
		reportError(errno, "poll");
	}
	return ret;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask)
{
	int ret = CALL_ORIG_FUNC(ppoll)(fds, nfds, timeout_ts, sigmask);
	if(ret == (int)-1) {
		reportError(errno, "ppoll");
	}
	return ret;
}

int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	int ret = CALL_ORIG_FUNC(prctl)(option, arg2, arg3, arg4, arg5);
	if(ret == (int)-1) {
		reportError(errno, "prctl");
	}
	return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret = CALL_ORIG_FUNC(pread)(fd, buf, count, offset);
	if(ret == (ssize_t)-1) {
		reportError(errno, "pread");
	}
	return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t ret = CALL_ORIG_FUNC(pwrite)(fd, buf, count, offset);
	if(ret == (ssize_t)-1) {
		reportError(errno, "pwrite");
	}
	return ret;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t ret = CALL_ORIG_FUNC(readv)(fd, iov, iovcnt);
	if(ret == (ssize_t)-1) {
		reportError(errno, "readv");
	}
	return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t ret = CALL_ORIG_FUNC(writev)(fd, iov, iovcnt);
	if(ret == (ssize_t)-1) {
		reportError(errno, "writev");
	}
	return ret;
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret = CALL_ORIG_FUNC(preadv)(fd, iov, iovcnt, offset);
	if(ret == (ssize_t)-1) {
		reportError(errno, "preadv");
	}
	return ret;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret = CALL_ORIG_FUNC(pwritev)(fd, iov, iovcnt, offset);
	if(ret == (ssize_t)-1) {
		reportError(errno, "pwritev");
	}
	return ret;
}

ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	ssize_t ret = CALL_ORIG_FUNC(process_vm_readv)(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
	if(ret == (ssize_t)-1) {
		reportError(errno, "process_vm_readv");
	}
	return ret;
}

ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	ssize_t ret = CALL_ORIG_FUNC(process_vm_writev)(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
	if(ret == (ssize_t)-1) {
		reportError(errno, "process_vm_writev");
	}
	return ret;
}

int quotactl(int cmd, const char *special, int id, caddr_t addr)
{
	int ret = CALL_ORIG_FUNC(quotactl)(cmd, special, id, addr);
	if(ret == (int)-1) {
		reportError(errno, "quotactl");
	}
	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret = CALL_ORIG_FUNC(read)(fd, buf, count);
	if(ret == (ssize_t)-1) {
		reportError(errno, "read");
	}
	return ret;
}

ssize_t readahead(int fd, off64_t offset, size_t count)
{
	ssize_t ret = CALL_ORIG_FUNC(readahead)(fd, offset, count);
	if(ret == (ssize_t)-1) {
		reportError(errno, "readahead");
	}
	return ret;
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
	ssize_t ret = CALL_ORIG_FUNC(readlink)(path, buf, bufsiz);
	if(ret == (ssize_t)-1) {
		reportError(errno, "readlink");
	}
	return ret;
}

int reboot(int cmd)
{
	int ret = CALL_ORIG_FUNC(reboot)(cmd);
	if(ret == (int)-1) {
		reportError(errno, "reboot");
	}
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t ret = CALL_ORIG_FUNC(recv)(sockfd, buf, len, flags);
	if(ret == (ssize_t)-1) {
		reportError(errno, "recv");
	}
	return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t ret = CALL_ORIG_FUNC(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
	if(ret == (ssize_t)-1) {
		reportError(errno, "recvfrom");
	}
	return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t ret = CALL_ORIG_FUNC(recvmsg)(sockfd, msg, flags);
	if(ret == (ssize_t)-1) {
		reportError(errno, "recvmsg");
	}
	return ret;
}

int remap_file_pages(void *addr, size_t size, int prot, ssize_t pgoff, int flags)
{
	int ret = CALL_ORIG_FUNC(remap_file_pages)(addr, size, prot, pgoff, flags);
	if(ret == (int)-1) {
		reportError(errno, "remap_file_pages");
	}
	return ret;
}

int rename(const char *oldpath, const char *newpath)
{
	int ret = CALL_ORIG_FUNC(rename)(oldpath, newpath);
	if(ret == (int)-1) {
		reportError(errno, "rename");
	}
	return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
	int ret = CALL_ORIG_FUNC(renameat)(olddirfd, oldpath, newdirfd, newpath);
	if(ret == (int)-1) {
		reportError(errno, "renameat");
	}
	return ret;
}

key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t keyring)
{
	key_serial_t ret = CALL_ORIG_FUNC(request_key)(type, description, callout_info, keyring);
	if(ret == (key_serial_t)-1) {
		reportError(errno, "request_key");
	}
	return ret;
}

int rmdir(const char *pathname)
{
	int ret = CALL_ORIG_FUNC(rmdir)(pathname);
	if(ret == (int)-1) {
		reportError(errno, "rmdir");
	}
	return ret;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	int ret = CALL_ORIG_FUNC(sigaction)(signum, act, oldact);
	if(ret == (int)-1) {
		reportError(errno, "sigaction");
	}
	return ret;
}

int sigpending(sigset_t *set)
{
	int ret = CALL_ORIG_FUNC(sigpending)(set);
	if(ret == (int)-1) {
		reportError(errno, "sigpending");
	}
	return ret;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int ret = CALL_ORIG_FUNC(sigprocmask)(how, set, oldset);
	if(ret == (int)-1) {
		reportError(errno, "sigprocmask");
	}
	return ret;
}

int sigsuspend(const sigset_t *mask)
{
	int ret = CALL_ORIG_FUNC(sigsuspend)(mask);
	if(ret == (int)-1) {
		reportError(errno, "sigsuspend");
	}
	return ret;
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	int ret = CALL_ORIG_FUNC(sigwaitinfo)(set, info);
	if(ret == (int)-1) {
		reportError(errno, "sigwaitinfo");
	}
	return ret;
}

int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
{
	int ret = CALL_ORIG_FUNC(sigtimedwait)(set, info, timeout);
	if(ret == (int)-1) {
		reportError(errno, "sigtimedwait");
	}
	return ret;
}

int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
{
	int ret = CALL_ORIG_FUNC(sched_setaffinity)(pid, cpusetsize, mask);
	if(ret == (int)-1) {
		reportError(errno, "sched_setaffinity");
	}
	return ret;
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
{
	int ret = CALL_ORIG_FUNC(sched_getaffinity)(pid, cpusetsize, mask);
	if(ret == (int)-1) {
		reportError(errno, "sched_getaffinity");
	}
	return ret;
}

int sched_setparam(pid_t pid, const struct sched_param *param)
{
	int ret = CALL_ORIG_FUNC(sched_setparam)(pid, param);
	if(ret == (int)-1) {
		reportError(errno, "sched_setparam");
	}
	return ret;
}

int sched_getparam(pid_t pid, struct sched_param *param)
{
	int ret = CALL_ORIG_FUNC(sched_getparam)(pid, param);
	if(ret == (int)-1) {
		reportError(errno, "sched_getparam");
	}
	return ret;
}

int sched_get_priority_max(int policy)
{
	int ret = CALL_ORIG_FUNC(sched_get_priority_max)(policy);
	if(ret == (int)-1) {
		reportError(errno, "sched_get_priority_max");
	}
	return ret;
}

int sched_get_priority_min(int policy)
{
	int ret = CALL_ORIG_FUNC(sched_get_priority_min)(policy);
	if(ret == (int)-1) {
		reportError(errno, "sched_get_priority_min");
	}
	return ret;
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	int ret = CALL_ORIG_FUNC(sched_setscheduler)(pid, policy, param);
	if(ret == (int)-1) {
		reportError(errno, "sched_setscheduler");
	}
	return ret;
}

int sched_getscheduler(pid_t pid)
{
	int ret = CALL_ORIG_FUNC(sched_getscheduler)(pid);
	if(ret == (int)-1) {
		reportError(errno, "sched_getscheduler");
	}
	return ret;
}
