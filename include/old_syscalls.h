#ifndef __OLD_SYSCALLS_H__
#define __OLD_SYSCALLS_H__

extern asmlinkage  long (*old_brk)(unsigned long);
extern asmlinkage  long (*old_chdir)(const char __user*);
extern asmlinkage   long (*old_chmod)(const char __user*, mode_t);
extern asmlinkage  long (*old_clock_gettime)(clockid_t, struct timespec __user*);
extern asmlinkage  long (*old_close)(int);
extern asmlinkage  long (*old_dup)(int);
extern asmlinkage long (*old_dup2)(int, int);
extern asmlinkage  long (*old_faccessat)(int, const char __user*, int);
extern asmlinkage  long (*old_fchmod)(int, mode_t);
extern asmlinkage  long (*old_fchown)(unsigned int, uid_t, gid_t);
extern asmlinkage  long (*old_fstat)(unsigned int, struct __old_kernel_stat __user*);
extern asmlinkage  long (*old_fcntl)(int, int, unsigned long);
extern asmlinkage  long (*old_futex)(u32 __user*, int, u32, struct timespec __user*, u32 __user*, u32);
extern asmlinkage  long (*old_getcwd)(char __user*, unsigned long);
extern asmlinkage  long (*old_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
extern asmlinkage  long (*old_getgid)(void);
extern asmlinkage  long (*old_getpid)(void);
extern asmlinkage  long (*old_getppid)(void);
extern asmlinkage  long (*old_ioctl)(unsigned int, unsigned int, unsigned long);
extern asmlinkage  long (*old_kill)(pid_t, int);
extern asmlinkage  long (*old_lseek)(unsigned int, off_t, unsigned int);
extern asmlinkage  long (*old_lstat)(const char __user *, struct __old_kernel_stat __user *);
extern asmlinkage  long (*old_mkdir)(const char __user *, umode_t);
extern asmlinkage  long (*old_mmap)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
extern asmlinkage  long (*old_munmap)(unsigned long, unsigned long);
extern asmlinkage  long (*old_write)(unsigned int, const char __user *, size_t count);
extern asmlinkage  long (*old_open)( const char __user *, int, mode_t);
extern asmlinkage  long (*old_access)(const char __user *, int);
extern asmlinkage  long (*old_mprotect)(unsigned long, size_t, unsigned long);
extern asmlinkage  long (*old_read)(unsigned int, char __user *, size_t count);
extern asmlinkage  long (*old_sysinfo)(struct sysinfo __user *);
extern asmlinkage  long (*old_sendto)(int, void __user*, size_t, unsigned int, struct sockaddr __user *, int);
extern asmlinkage  long (*old_socket)(int, int, int);
extern asmlinkage  long (*old_unlink)(const char __user *);
extern asmlinkage  long (*old_wait4)(pid_t, int __user *, int, struct rusage __user *);
extern asmlinkage  long (*old_utime)(char __user*, struct utimbuf __user*);
extern asmlinkage  long (*old_umask)(int);
extern asmlinkage  long (*old_uname)(struct old_utsname __user*);
extern asmlinkage  long (*old_stat)(const char __user *, struct __old_kernel_stat __user *);
extern asmlinkage  long (*old_setpgid)(pid_t, pid_t);
extern asmlinkage  long (*old_readlink)(const char __user*, char __user*, int);

#endif
