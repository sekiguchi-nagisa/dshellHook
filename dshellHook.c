#include "utils.h"
#include "autogensrc/headerList.h"

__attribute__((constructor))
static void init()
{
	initErrorCodeMap();
	saveOriginalFunction();
}

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
