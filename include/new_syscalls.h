#ifndef __NEW_SYSCALLS_H__
#define __NEW_SYSCALLS_H__

 long my_brk(unsigned long);
 long my_chdir(const char __user*);
 long my_chmod(const char __user*, mode_t);
 long my_clock_gettime(clockid_t, struct timespec __user*);
 long my_close(int);
 long my_dup(int);
 long my_dup2(int, int);
 long my_faccessat(int, const char __user*, int);
 long my_fchmod(int, mode_t);
 long my_fchown(unsigned int, uid_t, gid_t);
 long my_fstat(unsigned int, struct __old_kernel_stat __user*);
 long my_fcntl(int, int, unsigned long);
 long my_futex(u32 __user*, int, u32, struct timespec __user*, u32 __user*, u32);
 long my_getcwd(char __user*, unsigned long);
 long my_getdents64(unsigned int, struct linux_dirent64 __user *, unsigned int);
 long my_getgid(void);
 long my_getpid(void);
 long my_getppid(void);
 long my_ioctl(unsigned int, unsigned int, unsigned long);
 long my_lseek(unsigned int, off_t, unsigned int);
 long my_lstat(const char __user *, struct __old_kernel_stat __user *);
 long my_mkdir(const char __user *, umode_t);
 long my_mmap(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
 long my_munmap(unsigned long, unsigned long);
 long my_write(unsigned int, const char __user *, size_t);
 long my_open( const char __user * pathname , int flags , mode_t mode);
 long my_access( const char __user * pathname , int mode);
 long my_mprotect(unsigned long, size_t, unsigned long);
 long my_read(unsigned int, char __user *, size_t);
 long my_sysinfo(struct sysinfo __user *);
 long my_sendto(int, void __user*, size_t, unsigned int, struct sockaddr __user *, int);
 long my_socket(int, int, int);
 long my_unlink(const char __user *);
 long my_wait4(pid_t, int __user *, int, struct rusage __user *);
 long my_utime(char __user*, struct utimbuf __user*);
 long my_umask(int);
 long my_uname(struct old_utsname __user*);
 long my_stat(const char __user *, struct __old_kernel_stat __user *);
 long my_setpgid(pid_t, pid_t);
 long my_readlink(const char __user*, char __user*, int);

#endif
