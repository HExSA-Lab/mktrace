#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
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
#include "../include/syscall_tbl.h"
#include "../include/intercept.h"
#include "../include/worker.h"
#include "../include/handler.h"
#include "../include/bitnum.h"
void** syscall_table;
int (*fixed_set_memory_rw)(unsigned long, int);
int (*fixed_set_memory_ro)(unsigned long, int);
unsigned long  last_syslist;         //everytime dev_write is invoked, 
                                            //syscall_table needs to be 
                                            //restored based on this value
struct syscall_args syscall_task;
struct semaphore mr_sem;

asmlinkage  long (*old_brk)(unsigned long);
asmlinkage  long (*old_chdir)(const char __user*);
asmlinkage   long (*old_chmod)(const char __user*, mode_t);
asmlinkage  long (*old_clock_gettime)(clockid_t, struct timespec __user*);
asmlinkage  long (*old_close)(int);
asmlinkage  long (*old_dup)(int);
asmlinkage long (*old_dup2)(int, int);
asmlinkage  long (*old_faccessat)(int, const char __user*, int);
asmlinkage  long (*old_fchmod)(int, mode_t);
asmlinkage  long (*old_fchown)(unsigned int, uid_t, gid_t);
asmlinkage  long (*old_fstat)(unsigned int, struct __old_kernel_stat __user*);
asmlinkage  long (*old_fcntl)(int, int, unsigned long);
asmlinkage  long (*old_futex)(u32 __user*, int, u32, struct timespec __user*, u32 __user*, u32);
asmlinkage  long (*old_getcwd)(char __user*, unsigned long);
asmlinkage  long (*old_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
asmlinkage  long (*old_getgid)(void);
asmlinkage  long (*old_getpid)(void);
asmlinkage  long (*old_getppid)(void);
asmlinkage  long (*old_ioctl)(unsigned int, unsigned int, unsigned long);
asmlinkage  long (*old_kill)(pid_t, int);
asmlinkage  long (*old_lseek)(unsigned int, off_t, unsigned int);
asmlinkage  long (*old_lstat)(const char __user *, struct __old_kernel_stat __user *);
asmlinkage  long (*old_mkdir)(const char __user *, umode_t);
asmlinkage  long (*old_mmap)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
asmlinkage  long (*old_munmap)(unsigned long, unsigned long);
asmlinkage  long (*old_write)(unsigned int, const char __user *, size_t count);
asmlinkage  long (*old_open)( const char __user *, int, mode_t);
asmlinkage  long (*old_access)(const char __user *, int);
asmlinkage  long (*old_mprotect)(unsigned long, size_t, unsigned long);
asmlinkage  long (*old_read)(unsigned int, char __user *, size_t count);
asmlinkage  long (*old_sysinfo)(struct sysinfo __user *);
asmlinkage  long (*old_sendto)(int, void __user*, size_t, unsigned int, struct sockaddr __user *, int);
asmlinkage  long (*old_socket)(int, int, int);
asmlinkage  long (*old_unlink)(const char __user *);
asmlinkage  long (*old_wait4)(pid_t, int __user *, int, struct rusage __user *);
asmlinkage  long (*old_utime)(char __user*, struct utimbuf __user*);
asmlinkage  long (*old_umask)(int);
asmlinkage  long (*old_uname)(struct old_utsname __user*);
asmlinkage  long (*old_stat)(const char __user *, struct __old_kernel_stat __user *);
asmlinkage  long (*old_setpgid)(pid_t, pid_t);
asmlinkage  long (*old_readlink)(const char __user*, char __user*, int);

int restore_syscall_table(void)
{
    if (syscall_table != NULL)
    {
        int ret;
        unsigned long addr;

        //printk(KERN_INFO "before write_cr0\n");

        write_cr0(read_cr0() & ~CRO_WP);
        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        __flush_tlb_all();

        if (ret)
        {
            printk(KERN_INFO "unable to set the memory rw at %16lX\n", PAGE_ALIGN(addr) - PAGE_SIZE);
            return 1;
        }

        printk(KERN_INFO "trying to restore syscall_table\n");
        RESET_TBL_ENT(brk);
        RESET_TBL_ENT(chdir);
        RESET_TBL_ENT(chmod);
        RESET_TBL_ENT(clock_gettime);
        RESET_TBL_ENT(close);
        RESET_TBL_ENT(dup);
        RESET_TBL_ENT(dup2);
        RESET_TBL_ENT(faccessat);
        RESET_TBL_ENT(fchmod);
        RESET_TBL_ENT(fchown);
        RESET_TBL_ENT(fstat);
        RESET_TBL_ENT(getcwd);
        RESET_TBL_ENT(getdents64);
        RESET_TBL_ENT(getgid);
        RESET_TBL_ENT(getpid);
        RESET_TBL_ENT(getppid);
        RESET_TBL_ENT(ioctl);
        RESET_TBL_ENT(lseek);
        RESET_TBL_ENT(lstat);
        RESET_TBL_ENT(mkdir);
        RESET_TBL_ENT(write);
        RESET_TBL_ENT(mprotect);
        RESET_TBL_ENT(read);
        RESET_TBL_ENT(sysinfo);
        RESET_TBL_ENT(sendto);
        RESET_TBL_ENT(socket);
        RESET_TBL_ENT(unlink);
        RESET_TBL_ENT(utime);
        RESET_TBL_ENT(umask);
        RESET_TBL_ENT(uname);
        RESET_TBL_ENT(stat);
        RESET_TBL_ENT(setpgid);
        RESET_TBL_ENT(readlink);
	    RESET_TBL_ENT(futex);
	    RESET_TBL_ENT(wait4);
	    RESET_TBL_ENT(mmap);
	    RESET_TBL_ENT(munmap);
	    RESET_TBL_ENT(open);
	    RESET_TBL_ENT(access);
	    RESET_TBL_ENT(fcntl);
 

        printk(KERN_INFO "restored syscall_table\n");

        write_cr0(read_cr0() | CRO_WP);

        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        __flush_tlb_all();
    }

    return 0;
}
//this function store the replaced syscall entry into shadow_table
//and replace the syscall_table with our wrapping functions
void replace_table(unsigned long syslist)
{
        if (syscall_table != NULL){
        int ret;
        unsigned long addr;
        unsigned long old_cr0;
        old_cr0 = read_cr0();

        write_cr0(old_cr0 & ~CRO_WP);
        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        write_cr3(virt_to_phys(current->mm->pgd));
        __flush_tlb_all();

        if (ret)
        {
            printk(KERN_INFO "unable to set the memory rw at %16lX\n", PAGE_ALIGN(addr) - PAGE_SIZE);
            return ;
        }
        SET_TBL_ENT(brk);
        SET_TBL_ENT(chdir);
        SET_TBL_ENT(chmod);
        SET_TBL_ENT(clock_gettime);
        SET_TBL_ENT(close);
        SET_TBL_ENT(dup);
        SET_TBL_ENT(dup2);
        SET_TBL_ENT(faccessat);
        SET_TBL_ENT(fchmod);
        SET_TBL_ENT(fchown);
        SET_TBL_ENT(fstat);
        SET_TBL_ENT(getcwd);
        SET_TBL_ENT(getdents64);
        SET_TBL_ENT(getgid);
        SET_TBL_ENT(getpid);
        SET_TBL_ENT(getppid);
        SET_TBL_ENT(ioctl);
        SET_TBL_ENT(lseek);
        SET_TBL_ENT(lstat);
        SET_TBL_ENT(mkdir);
        SET_TBL_ENT(write);
        SET_TBL_ENT(mprotect);
        SET_TBL_ENT(read);
        SET_TBL_ENT(sysinfo);
        SET_TBL_ENT(sendto);
        SET_TBL_ENT(socket);
        SET_TBL_ENT(unlink);
        SET_TBL_ENT(utime);
        SET_TBL_ENT(umask);
        SET_TBL_ENT(uname);
        SET_TBL_ENT(stat);
        SET_TBL_ENT(setpgid);
        SET_TBL_ENT(readlink);
	    SET_TBL_ENT(futex);
	    SET_TBL_ENT(wait4);
	    SET_TBL_ENT(mmap);
	    SET_TBL_ENT(munmap);
	    SET_TBL_ENT(open);
	    SET_TBL_ENT(access);
	    SET_TBL_ENT(fcntl);
        last_syslist = syslist;

        write_cr0(old_cr0);
        ret = fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        write_cr3(virt_to_phys(current->mm->pgd));
        __flush_tlb_all();
    }
    else
    {
        printk(KERN_INFO "replace_table cannot find the location of syscall_table\n");
    }
}



int init_syscall_table(void)
{
    /* 
     * this function finds out the mem addr of syscall table,
     * then replace some entries of it with our wrapping function
     */

    printk(KERN_INFO "start to find syscall addr\n");
    syscall_table = (void**) find_syscall_table();
    printk(KERN_INFO "syscall_table addr:0x%p\n", syscall_table);

    fixed_set_memory_rw = (void *) kallsyms_lookup_name("set_memory_rw");
    if (!fixed_set_memory_rw)
    {
        printk(KERN_INFO "unable to find set_memory_rw symbol\n");
    }

    fixed_set_memory_ro = (void *) kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro)
    {
        printk(KERN_INFO "unable to find set_memory_ro symbol\n");
    }
    last_syslist = 0;
    syscall_task.status = PAUSE_DELEGATEE;

    printk(KERN_INFO "init_syscall_table done\n");
    return 0;
}

unsigned long** find_syscall_table(void)
{
    unsigned long ptr;
    unsigned long *p;

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
    unsigned long ret = kallsyms_lookup_name("syscall_table");
    printk("Found syscall table at %p\n", (void*)ret);
    return ret;
#else 

    for (ptr = (unsigned long) sys_close;
            ptr < (unsigned long) &loops_per_jiffy;
            ptr += sizeof(void*)){

        p = (unsigned long*) ptr;

        if(p[__NR_close] == (unsigned long) sys_close){
            printk("found syscall table");
            return (unsigned long**) p;
        }
    }
    printk("syscall table not found");
    return NULL;
#endif
}
