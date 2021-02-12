#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sys.h>
#include <linux/io.h>
#include <linux/mmu_context.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include "../include/new_syscalls.h"
#include "../include/old_syscalls.h"
#include "../include/intercept.h"
#include "../include/handler.h"
#include "../include/syscall_tbl.h"
#include "../include/worker.h"

long my_brk(unsigned long brk)
{
   syscall_wrapper(__NR_brk, old_brk(brk));
}

 long my_chdir(const char __user* filename)
{
   syscall_wrapper(__NR_chdir, old_chdir(filename));
}

 long my_chmod(const char* filename, mode_t mode)
{
   syscall_wrapper(__NR_chmod, old_chmod(filename, mode));
}

 long my_clock_gettime(clockid_t clk_id, struct timespec __user* tp)
{
    syscall_wrapper(__NR_clock_gettime, old_clock_gettime(clk_id, tp));
}

 long my_close(int fd)
{
    syscall_wrapper(__NR_close, old_close(fd));
}

 long my_dup(int oldfd)
{
    syscall_wrapper(__NR_dup, old_dup(oldfd));
}

 long my_dup2(int oldfd, int newfd)
{
    syscall_wrapper(__NR_dup2, old_dup2(oldfd, newfd));
}
 long my_faccessat(int dfd, const char __user* filename, int mode)
{
    syscall_wrapper(__NR_faccessat, old_faccessat(dfd, filename, mode));
}

 long my_fchmod(int fd, mode_t mode)
{
    syscall_wrapper(__NR_fchmod, old_fchmod(fd, mode));
}

 long my_fchown(unsigned int fd, uid_t owner, gid_t group)
{
    syscall_wrapper(__NR_fchown, old_fchown(fd, owner, group));
}

 long my_fstat(unsigned int fd, struct __old_kernel_stat __user* buf)
{
    syscall_wrapper(__NR_fstat, old_fstat(fd, buf));
}

 long my_fcntl(int fd, int cmd, unsigned long arg)
{
    syscall_wrapper(__NR_fcntl, old_fcntl(fd, cmd, arg));
}

 long my_futex(u32 __user* uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
    syscall_wrapper(__NR_futex, old_futex(uaddr, op, val, utime, uaddr2, val3));
}

 long my_getcwd(char __user* buf, unsigned long size)
{
    syscall_wrapper(__NR_getcwd, old_getcwd(buf, size));
}

 long my_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    syscall_wrapper(__NR_getdents64, old_getdents64(fd, dirent, count));
}


 long my_getgid(void)
{
    syscall_wrapper(__NR_getgid, old_getgid());
}

 long my_getpid(void)
{
    syscall_wrapper(__NR_getpid, old_getpid());
}

 long my_getppid(void)
{
    syscall_wrapper(__NR_getppid, old_getppid());
}

 long my_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    syscall_wrapper(__NR_ioctl, old_ioctl(fd, cmd, arg));
}

 long my_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
    syscall_wrapper(__NR_lseek, old_lseek(fd, offset, whence));
}

 long my_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    syscall_wrapper(__NR_lstat, old_lstat(filename, statbuf));
}

 long my_mkdir(const char __user *pathname, umode_t mode)
{
    syscall_wrapper(__NR_mkdir, old_mkdir(pathname, mode));
}
 long my_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    syscall_wrapper(__NR_mmap, old_mmap(addr, len, prot, flags, fd, pgoff));
}
 long my_munmap(unsigned long addr, unsigned long len)
{
    syscall_wrapper(__NR_munmap, old_munmap(addr, len));
}

 long my_write(unsigned int fd, const char __user *buf, size_t count)
{
    syscall_wrapper(__NR_write, old_write(fd, buf, count));
}

 long my_access(const char __user * pathname, int mode)
{
    syscall_wrapper(__NR_access, old_access(pathname, mode));
}

 long my_open( const char __user * pathname , int flags , mode_t mode)
{
    syscall_wrapper(__NR_open, old_open(pathname, flags, mode));
}

 long my_mprotect(unsigned long start, size_t len, unsigned long prot)
{
    syscall_wrapper(__NR_mprotect, old_mprotect(start, len, prot));
}

 long my_read(unsigned int fd, char __user *buf, size_t count)
{
    syscall_wrapper(__NR_read, old_read(fd, buf, count));
}

 long my_sysinfo(struct sysinfo __user *info)
{
    syscall_wrapper(__NR_sysinfo, old_sysinfo(info));
}

 long my_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user* addr, int addr_len)
{
    syscall_wrapper(__NR_sendto, old_sendto(fd, buff, len, flags, addr, addr_len));
}

 long my_socket(int family, int type, int protocol)
{
    syscall_wrapper(__NR_socket, old_socket(family, type, protocol));
}

 long my_unlink(const char __user *pathname)
{
    syscall_wrapper(__NR_unlink, old_unlink(pathname));
}

 long my_wait4(pid_t upid, int __user * stat_addr, int options, struct rusage __user* ru)
{
    syscall_wrapper(__NR_wait4, old_wait4(upid, stat_addr, options, ru)); 
}

 long my_utime(char __user *filename, struct utimbuf __user *times)
{
    syscall_wrapper(__NR_utime, old_utime(filename, times));
}

 long my_umask(int mask)
{
    syscall_wrapper(__NR_umask, old_umask(mask));
}

 long my_uname(struct old_utsname __user *name)
{
    syscall_wrapper(__NR_uname, old_uname(name));
}

 long my_stat(const char __user* filename, struct __old_kernel_stat __user* statbuf)
{
    syscall_wrapper(__NR_stat, old_stat(filename, statbuf));
}

 long my_setpgid(pid_t pid, pid_t pgid)
{
    syscall_wrapper(__NR_setpgid, old_setpgid(pid, pgid));
}

 long my_readlink(const char __user *path, char __user *buf, int bufsiz)
{
    syscall_wrapper(__NR_readlink, old_readlink(path, buf, bufsiz));
}
