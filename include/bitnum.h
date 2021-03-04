#ifndef __MKTRACE_BIT_NUM
#define __MKTRACE_BIT_NUM

#define __BN_brk            (1)
#define __BN_chdir          (1UL << 1)
#define __BN_chmod          (1UL << 2) 
#define __BN_clock_gettime  (1UL << 3) 
#define __BN_close          (1UL << 5) 
#define __BN_dup            (1UL << 6) 
#define __BN_dup2           (1UL << 7) 
#define __BN_faccessat      (1UL << 9) 
#define __BN_fchmod         (1UL << 10) 
#define __BN_fchown         (1UL << 11)
#define __BN_fcntl          (1UL << 12)
#define __BN_fstat          (1UL << 13)
#define __BN_futex          (1UL << 14)
#define __BN_getcwd         (1UL << 15)
#define __BN_getdents64     (1UL << 16)
#define __BN_getegid        (1UL << 17)
#define __BN_getgid         (1UL << 19)
#define __BN_getpid         (1UL << 22)
#define __BN_getppid        (1UL << 23)
#define __BN_ioctl          (1UL << 25)
#define __BN_lseek          (1UL << 27)
#define __BN_lstat          (1UL << 28)
#define __BN_mkdir          (1UL << 29)
#define __BN_mprotect       (1UL << 31)
#define __BN_read           (1UL << 38)
#define __BN_readlink       (1UL << 39)
#define __BN_sendto         (1UL << 43)
#define __BN_setpgid        (1UL << 44)
#define __BN_socket         (1UL << 47)
#define __BN_stat           (1UL << 48)
#define __BN_sysinfo        (1UL << 49)
#define __BN_umask          (1UL << 50)
#define __BN_uname          (1UL << 51)
#define __BN_unlink         (1UL << 52)
#define __BN_utime          (1UL << 53)
#define __BN_wait4          (1UL << 55)
#define __BN_write          (1UL << 56)
#define __BN_mmap           (1UL << 57)
#define __BN_munmap         (1UL << 58)
#define __BN_access         (1UL << 59)
#define __BN_open           (1UL << 60)
#endif