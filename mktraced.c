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
#include <linux/version.h>
#include <linux/kallsyms.h>

#define CRO_WP 0x00010000
#define DEVICE_NAME "cl_sf"
#define CLASS_NAME  "cl"

MODULE_AUTHOR("Conghao Liu <cliu115@hawk.iit.edu>");
MODULE_DESCRIPTION("Syscall proxy daemon");

#define syscall_wrapper(syscall_number, old_call)   \
({                                                  \
    long result;\
    struct syscall_args args;\
    asm volatile("movq %%rax, %0 \t\n\
                  movq %%rdi, %1 \t\n\
                  movq %%rsi, %2 \t\n\
                  movq %%rdx, %3 \t\n\
                  movq %%r10, %4 \t\n\
                  movq %%r8,  %5 \t\n\
                  movq %%r9,  %6"\
                 :"=m" (args.call_num), "=m" (args.arg1), "=m" (args.arg2),\
                  "=m" (args.arg3), "=m" (args.arg4), "=m" (args.arg5),\
                  "=m" (args.arg6)\
                 :\
                 :"%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9"\
                 );\
    if (current->pid == targetPid && pidFlag == 1){\
        syscall_task.arg1 = args.arg1;\
        syscall_task.arg2 = args.arg2;\
        syscall_task.arg3 = args.arg3;\
        syscall_task.arg4 = args.arg4;\
        syscall_task.arg5 = args.arg5;\
        syscall_task.arg6 = args.arg6;\
        syscall_task.call_num = syscall_number;\
        syscall_task.mm = current->mm;\
        syscall_task.active_mm = current->active_mm;\
        syscall_task.files = current->files;\
        syscall_task.fs = current->fs;\
        syscall_task.nsproxy = current->nsproxy;\
        syscall_task.group_leader = current->group_leader;\
        syscall_task.real_parent = current->real_parent;\
        syscall_task.audit_context = current->audit_context;\
        syscall_task.cred = current->cred;\
        syscall_task.real_cred = current->real_cred;\
        syscall_task.status = 0;\
        while(!syscall_task.status) wake_up_process(task);\
        result = syscall_task.ret;\
    if (syscall_number == __NR_mmap){\
        printk(KERN_INFO "ret value of mmap is %ld\n", result);\
    }\
    }\
    else{\
        result = old_call;\
    }\
    return result;\
})

/*
*/
#define HANDLE_UP   \
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    struct fs_struct* old_fs;\
    struct nsproxy* old_nsproxy;\
    struct task_struct* old_group_leader;\
    struct task_struct __rcu *old_real_parent;\
    unsigned int old_personality;\
    struct audit_context* old_audit_context;\
    unsigned long old_cr3;\
    struct cred __rcu* old_cred;\
    struct cred __rcu* old_real_cred;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    old_fs = current->fs;\
    old_nsproxy = current->nsproxy;\
    old_group_leader = current->group_leader;\
    old_real_parent = current->real_parent;\
    old_personality = current->personality;\
    old_audit_context = current->audit_context;\
    old_cr3 = __read_cr3();\
    old_cred = current->cred;\
    old_real_cred = current->real_cred;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    current->fs = syscall_task.fs;\
    current->nsproxy = syscall_task.nsproxy;\
    current->group_leader = syscall_task.group_leader;\
    current->real_parent = syscall_task.real_parent;\
    current->personality = syscall_task.personality;\
    current->audit_context = syscall_task.audit_context;\
    write_cr3(virt_to_phys(current->mm->pgd));\
    current->cred = syscall_task.cred;\
    current->real_cred = syscall_task.real_cred;


#define HANDLE_BOT  \
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    current->fs = old_fs;\
    current->nsproxy = old_nsproxy;\
    current->group_leader = old_group_leader;\
    current->real_parent = old_real_parent;\
    current->personality = old_personality;\
    current->audit_context = old_audit_context;\
    write_cr3(old_cr3);\
    current->cred = old_cred;\
    current->real_cred = old_real_cred;\
    break;

#define HANDLE_CALL0(CALL_NAME)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)();\
    HANDLE_BOT;\
})

#define HANDLE_CALL1(CALL_NAME, AT1)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1);\
    HANDLE_BOT;\
 })

#define HANDLE_CALL2(CALL_NAME, AT1, AT2)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2);\
    HANDLE_BOT;\
})

#define HANDLE_CALL3(CALL_NAME, AT1, AT2, AT3)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3);\
    HANDLE_BOT;\
})

#define HANDLE_CALL4(CALL_NAME, AT1, AT2, AT3, AT4)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4);\
    HANDLE_BOT;\
})

#define HANDLE_CALL5(CALL_NAME, AT1, AT2, AT3, AT4, AT5)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4,\
                                    (AT5)syscall_task.arg5);\
    HANDLE_BOT;\
})

#define HANDLE_CALL6(CALL_NAME, AT1, AT2, AT3, AT4, AT5, AT6)\
({\
    HANDLE_UP;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4,\
                                    (AT5)syscall_task.arg5,\
                                    (AT6)syscall_task.arg6);\
    HANDLE_BOT;\
})



/*
#define HANDLE_CALL0(CALL_NAME)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)(void);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL1(CALL_NAME, AT1)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL2(CALL_NAME, AT1, AT2)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL3(CALL_NAME, AT1, AT2, AT3)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL4(CALL_NAME, AT1, AT2, AT3, AT4)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL5(CALL_NAME, AT1, AT2, AT3, AT4, AT5)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4,\
                                    (AT5)syscall_task.arg5);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

#define HANDLE_CALL6(CALL_NAME, AT1, AT2, AT3, AT4, AT5, AT6)\
    struct mm_struct* old_mm;\
    struct mm_struct* old_active_mm;\
    struct files_struct* old_files;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    current->mm = syscall_task.mm;\
    current->active_mm = syscall_task.active_mm;\
    current->files = syscall_task.files;\
    syscall_task.ret = (*CALL_NAME)((AT1)syscall_task.arg1,\
                                    (AT2)syscall_task.arg2,\
                                    (AT3)syscall_task.arg3,\
                                    (AT4)syscall_task.arg4,\
                                    (AT5)syscall_task.arg5,\
                                    (AT6)syscall_task.arg6);\
    syscall_task.status = 1;\
    current->mm = old_mm;\
    current->active_mm = old_active_mm;\
    current->files = old_files;\
    break;

*/


static struct task_struct* task;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Conghao Liu");
MODULE_DESCRIPTION("syscall forwarding simulation");
MODULE_VERSION("0,1");

//static void* shadow_table[600];    //not sure the length of the actual syscall_table
//this contains the replaced syscall entry

static int            majorNumber;
static pid_t          targetPid;
static int            pidFlag;              //0:pid unset 1:pid set
static struct class*  clcharClass  = NULL;
static struct device* clcharDevice = NULL;

static int (*fixed_set_memory_rw)(unsigned long, int);
static int (*fixed_set_memory_ro)(unsigned long, int);
static unsigned long (*iopa_ptr)(unsigned long);

static ssize_t dev_write(struct file*, const char*, size_t, loff_t*);
static struct file_operations fops = {
    .write = dev_write,
};

asmlinkage static int (*old_brk)(void*);
asmlinkage static int (*old_chdir)(const char*);
asmlinkage static int (*old_chmod)(const char*, mode_t);
asmlinkage static int (*old_clock_gettime)(clockid_t, struct timespec*);
asmlinkage static int (*old_close)(int);
asmlinkage static int (*old_dup)(int);
asmlinkage static int (*old_dup2)(int, int);
//asmlinkage static int (*old_execve)(const char*, char** const, char** const);
asmlinkage static int (*old_faccessat)(int, const char*, int, int);
asmlinkage static int (*old_fchmod)(int, mode_t);
asmlinkage static int (*old_fchown)(int, uid_t, gid_t);
asmlinkage static int (*old_fstat)(int, struct stat*);
asmlinkage static int (*old_futex)(int*, int, int, const struct timespec*, int*, int);
asmlinkage static long (*old_getcwd)(char __user*, size_t);
asmlinkage static long (*old_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
asmlinkage static long (*old_getgid)(void);
asmlinkage static long (*old_getpid)(void);
asmlinkage static long (*old_getppid)(void);
asmlinkage static long (*old_ioctl)(unsigned int, unsigned int, unsigned long);
asmlinkage static long (*old_kill)(pid_t, int);
asmlinkage static long (*old_lseek)(unsigned int, off_t, unsigned int);
asmlinkage static long (*old_lstat)(const char __user *, struct __old_kernel_stat __user *);
asmlinkage static long (*old_mkdir)(const char __user *, umode_t);
asmlinkage static long (*old_mmap)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
asmlinkage static long (*old_write)(unsigned int, const char __user *, size_t count);
asmlinkage static long (*old_mprotect)(unsigned long, size_t, unsigned long);
asmlinkage static long (*old_read)(unsigned int, char __user *, size_t count);
asmlinkage static long (*old_sysinfo)(struct sysinfo __user *);
asmlinkage static long (*old_sendto)(int, void __user*, size_t, unsigned int, struct sockaddr __user *, int);
asmlinkage static long (*old_socket)(int, int, int);
asmlinkage static long (*old_unlink)(const char __user *);
asmlinkage static long (*old_wait4)(pid_t, int __user *, int, struct rusage __user *);
asmlinkage static long (*old_utime)(char __user*, struct utimbuf __user*);
asmlinkage static long (*old_umask)(int);
asmlinkage static long (*old_uname)(struct old_utsname __user*);
asmlinkage static long (*old_stat)(const char __user *, struct __old_kernel_stat __user *);
asmlinkage static long (*old_nanosleep)(const struct timespec*, struct timespec*);
asmlinkage static long (*old_setpgid)(pid_t, pid_t);
asmlinkage static long (*old_readlink)(const char __user*, char __user*, int);


static int my_brk(void*);
static int my_chdir(const char*);
static int my_chmod(const char*, mode_t);
static int my_clock_gettime(clockid_t, struct timespec*);
static int my_close(int);
static int my_dup(int);
static int my_dup2(int, int);
//static int my_execve(const char*, char** const, char** const);
static int my_faccessat(int, const char*, int, int);
static int my_fchmod(int, mode_t);
static int my_fchown(int, uid_t, gid_t);
static int my_fstat(int, struct stat*);
static int my_futex(int*, int, int, const struct timespec*, int*, int);
static long my_getcwd(char __user*, size_t);
static long my_getdents64(unsigned int, struct linux_dirent64 __user *, unsigned ing);
static long my_getgid(void);
static long my_getpid(void);
static long my_getppid(void);
static long my_ioctl(unsigned int, unsigned int, unsigned long);
static long my_kill(pid_t, int);
static long my_lseek(unsigned int, off_t, unsigned int);
static long my_lstat(const char __user *, struct __old_kernel_stat __user *);
static long my_mkdir(const char __user *, umode_t);
static long my_mmap(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
static long my_write(unsigned int, const char __user *, size_t);
static long my_mprotect(unsigned long, size_t, unsigned long);
static long my_read(unsigned int, char __user *, size_t);
static long my_sysinfo(struct sysinfo __user *);
static long my_sendto(int, void __user*, size_t, unsigned int, struct sockaddr __user *, int);
static long my_socket(int, int, int);
static long my_unlink(const char __user *);
static long my_wait4(pid_t, int __user *, int, struct rusage __user *);
static long my_utime(char __user*, struct utimbuf __user*);
static long my_umask(int);
static long my_uname(struct old_utsname __user*);
static long my_stat(const char __user *, struct __old_kernel_stat __user *);
static long my_nanosleep(const struct timespec*, struct timespec*);
static long my_setpgid(pid_t, pid_t);
static long my_readlink(const char __user*, char __user*, int);




static void** syscall_table;

static struct syscall_args{
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long ret;
    volatile int status; //0: ongoing 1:finished
    unsigned long call_num;

    struct mm_struct* mm;
    struct mm_struct* active_mm;
    struct files_struct* files;
    struct fs_struct* fs;
    struct cred __rcu* cred;
    struct cred __rcu* real_cred;
    struct nsproxy* nsproxy;
    struct task_struct* group_leader;
    struct task_struct __rcu *real_parent;
    unsigned int personality;
    struct audit_context* audit_context;
    //struct sighand_struct* sighand;
    //struct signal_struct* signal;

} syscall_task;


static struct task_struct* worker_id;

static unsigned long** find_syscall_table(void)
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
static int worker(void* data){
    printk("worker launched\n");
    while(1)
    {

        //printk(KERN_INFO "about to check syscall_task value\n");
        if(syscall_task.status == 0)
        {
            printk(KERN_INFO "syscall_task value checked\n");
            printk(KERN_INFO "syscall_num = %lu\n", syscall_task.call_num);
            switch(syscall_task.call_num)
            {

                case __NR_brk:
                    {
                        //int (*func)(void*);
                        //func = shadow_table[__NR_brk];
                        /*
                        struct mm_struct* old_mm;
                        struct mm_struct* old_active_mm;

                        old_mm = current->mm;
                        old_active_mm = current->active_mm;

                        current->mm = syscall_task.mm;
                        current->active_mm = syscall_task.active_mm;
                        
                        //printk(KERN_INFO "sys_brk called!!!!!\n");
                        syscall_task.ret = (*old_brk)((void*)syscall_task.arg1);
                        //printk(KERN_INFO "sys_brk returned\n");
                        syscall_task.status = 1;

                        current->mm = old_mm;
                        current->active_mm = old_active_mm;
                        break;
                        */
                        HANDLE_CALL1(old_brk, void*);
                    }
                case __NR_chdir:
                    {
                        /*
                           int (*func)(const char* path);
                           func = shadow_table[__NR_chdir];
                           syscall_task.ret = (*func)((char*) syscall_task.arg1);
                           syscall_task.status = 1;
                            break;
                           */
                        HANDLE_CALL1(old_chdir, const char*);
                    }
                case __NR_chmod:
                    {
                        /*
                           int (*func)(const char* path, mode_t);
                           func = shadow_table[__NR_chmod];
                           syscall_task.ret = (*func)((char*) syscall_task.arg1, (mode_t) syscall_task.arg2);
                           syscall_task.status = 1;
                            break;
                           */
                        HANDLE_CALL2(old_chmod, const char*, mode_t);
                    }
                case __NR_clock_gettime:
                    {
                        HANDLE_CALL2(old_clock_gettime, clockid_t, struct timespec*);
                    }
                case __NR_close:
                    {
                        HANDLE_CALL1(old_close, int);
                    }
                case __NR_dup:
                    {
                        HANDLE_CALL1(old_dup, int);
                    }
                case __NR_dup2:
                    {
                        HANDLE_CALL2(old_dup2, int, int);
                    }
                    /*
                case __NR_execve:
                    {
                        HANDLE_CALL3(old_execve, const char*, char** const, char** const);
                    }
                    */
                case __NR_faccessat:
                    {
                        HANDLE_CALL4(old_faccessat, int, const char*, int, int);
                    }
                case __NR_fchmod:
                    {
                        HANDLE_CALL2(old_fchmod, int, mode_t);
                    }
                case __NR_fchown:
                    {
                        HANDLE_CALL3(old_fchown, int, uid_t, gid_t);
                    }
                case __NR_fstat:
                    {
                        HANDLE_CALL2(old_fstat, int, struct stat*);
                    }
                case __NR_futex:
                    {
                        HANDLE_CALL6(old_futex, int*, int, int, const struct timespec*, int*, int);
                    }
                case __NR_getcwd:
                    {
                        HANDLE_CALL2(old_getcwd, char*, unsigned long);
                    }
                case __NR_getdents64:
                    {
                        HANDLE_CALL3(old_getdents64, unsigned int, struct linux_dirent64*, unsigned int);
                    }
                case __NR_getgid:
                    {
                        //this is a special case since current->cred is const
                        /*
                       syscall_task.ret = (unsigned long)((syscall_task.cred)->gid);
                       syscall_task.status = 1;
                       */
                       break;
                    }
                case __NR_getpid:
                    {
                        HANDLE_CALL0(old_getpid);
                    }
                case __NR_getppid:
                    {
                        HANDLE_CALL0(old_getppid);
                    }
                case __NR_ioctl:
                    {
                        HANDLE_CALL3(old_ioctl, unsigned int, unsigned int, unsigned long);
                    }
                case __NR_kill:
                    {
                        HANDLE_CALL2(old_kill, pid_t, int);
                    }
                case __NR_lseek:
                    {
                        HANDLE_CALL3(old_lseek, unsigned int, off_t, unsigned int);
                    }
                case __NR_lstat:
                    {
                        HANDLE_CALL2(old_lstat, char*, struct __old_kernel_stat*);
                    }
                case __NR_mkdir:
                    {
                        HANDLE_CALL2(old_mkdir, char*, umode_t);
                    }
                case __NR_mmap:
                    {
                        HANDLE_CALL6(old_mmap, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
                    }
                case __NR_write:
                    {
                        HANDLE_CALL3(old_write, unsigned int, char*, size_t);
                    }
                case __NR_mprotect:
                    {
                        HANDLE_CALL3(old_mprotect, unsigned long, size_t, unsigned long);
                    }
                case __NR_read:
                    {
                        HANDLE_CALL3(old_read, unsigned int, char*, size_t);
                    }
                case __NR_sysinfo:
                    {
                        HANDLE_CALL1(old_sysinfo, struct sysinfo*);
                    }
                case __NR_sendto:
                    {
                        HANDLE_CALL6(old_sendto, int, void*, size_t, unsigned int, struct sockaddr*, int);
                    }
                case __NR_socket:
                    {
                        HANDLE_CALL3(old_socket, int, int ,int);
                    }
                case __NR_unlink:
                    {
                        HANDLE_CALL1(old_unlink, const char __user *);
                    }
                case __NR_wait4:
                    {
                        HANDLE_CALL4(old_wait4, pid_t, int __user *, int, struct rusage*);
                    }
                case __NR_utime:
                    {
                        HANDLE_CALL2(old_utime, char __user *, struct utimbuf __user*);
                    }
                case __NR_umask:
                    {
                        HANDLE_CALL1(old_umask, int);
                    }
                case __NR_uname:
                    {
                        HANDLE_CALL1(old_uname, struct old_utsname __user*);
                    }
                case __NR_stat:
                    {
                        HANDLE_CALL2(old_stat, const char __user *, struct __old_kernel_stat __user*);
                    }
                case __NR_nanosleep:
                    {
                        HANDLE_CALL2(old_nanosleep, const struct timespec*, struct timespec*);
                    }
                case __NR_setpgid:
                    {
                        HANDLE_CALL2(old_setpgid, pid_t, pid_t);
                    }
                case __NR_readlink:
                    {
                        HANDLE_CALL3(old_readlink, const char __user*, char __user*, int);
                    }
                default:
                    {

                    }
            }
        }
        else
        {
            task = current;
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
        }

        if (kthread_should_stop()){
            printk(KERN_INFO "worker thread returns\n");
            return 0;
        }
        //printk(KERN_INFO "syscall_task value checked\n");
    }
    
    /* 
    */
    return 0;
}

static int my_brk(void* addr)
{
    /*
    int result;
    result = old_brk(addr);
    return result;
      */

    syscall_wrapper(__NR_brk, old_brk(addr));
}

static int my_chdir(const char* path)
{
    /*
    int result;
    syscall_task.arg1 = (unsigned long long) path;
    syscall_task.call_num = __NR_chdir;
    syscall_task.status = 0;
    wake_up_process(task);
    while(!syscall_task.status);
    result = syscall_task.ret;
    return result;
    */
    syscall_wrapper(__NR_chdir, old_chdir(path));
}

static int my_chmod(const char* pathname, mode_t mode)
{
    /*
    int result;
    syscall_task.arg1 = (unsigned long long) pathname;
    syscall_task.arg2 = (unsigned long long) mode;
    syscall_task.call_num = __NR_chmod;
    syscall_task.status = 0;
    wake_up_process(task);
    while(!syscall_task.status);
    result = syscall_task.ret;
    return result;
    */
    syscall_wrapper(__NR_chmod, old_chmod(pathname, mode));
}

static int my_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    syscall_wrapper(__NR_clock_gettime, old_clock_gettime(clk_id, tp));
}

static int my_close(int fd)
{
    syscall_wrapper(__NR_close, old_close(fd));
}

static int my_dup(int oldfd)
{
    syscall_wrapper(__NR_dup, old_dup(oldfd));
}

static int my_dup2(int oldfd, int newfd)
{
    syscall_wrapper(__NR_dup2, old_dup2(oldfd, newfd));
}

/*
static int my_execve(const char* filename, char* const argv[], char* const envp[])
{
    syscall_wrapper(__NR_execve, old_execve(filename, argv, envp));
}
*/

static int my_faccessat(int dirfd, const char* pathname, int mode, int flags)
{
    syscall_wrapper(__NR_faccessat, old_faccessat(dirfd, pathname, mode, flags));
}

static int my_fchmod(int fd, mode_t mode)
{
    syscall_wrapper(__NR_fchmod, old_fchmod(fd, mode));
}

static int my_fchown(int fd, uid_t owner, gid_t group)
{
    syscall_wrapper(__NR_fchown, old_fchown(fd, owner, group));
}

static int my_fstat(int fd, struct stat* buf)
{
    syscall_wrapper(__NR_fstat, old_fstat(fd, buf));
}

static int my_futex(int* uaddr, int futex_op, int val, const struct timespec* timeout, int* uaddr2, int val3)
{
    syscall_wrapper(__NR_futex, old_futex(uaddr, futex_op, val, timeout, uaddr2, val3));
}

static long my_getcwd(char __user* buf, unsigned long size)
{
    syscall_wrapper(__NR_getcwd, old_getcwd(buf, size));
}

static long my_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    syscall_wrapper(__NR_getdents64, old_getdents64(fd, dirent, count));
}

static long my_getgid(void)
{
    syscall_wrapper(__NR_getgid, old_getgid());
}

static long my_getpid(void)
{
    syscall_wrapper(__NR_getpid, old_getpid());
}

static long my_getppid(void)
{
    syscall_wrapper(__NR_getppid, old_getppid());
}

static long my_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    syscall_wrapper(__NR_ioctl, old_ioctl(fd, cmd, arg));
}

static long my_kill(pid_t pid, int sig)
{
    syscall_wrapper(__NR_kill, old_kill(pid, sig));
}

static long my_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
    syscall_wrapper(__NR_lseek, old_lseek(fd, offset, whence));
}

static long my_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    syscall_wrapper(__NR_lstat, old_lstat(filename, statbuf));
}

static long my_mkdir(const char __user *pathname, umode_t mode)
{
    syscall_wrapper(__NR_mkdir, old_mkdir(pathname, mode));
}

static long my_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    syscall_wrapper(__NR_mmap, old_mmap(addr, len, prot, flags, fd, pgoff));
}

static long my_write(unsigned int fd, const char __user *buf, size_t count)
{
    syscall_wrapper(__NR_write, old_write(fd, buf, count));
}

static long my_mprotect(unsigned long start, size_t len, unsigned long prot)
{
    syscall_wrapper(__NR_mprotect, old_mprotect(start, len, prot));
}

static long my_read(unsigned int fd, char __user *buf, size_t count)
{
    syscall_wrapper(__NR_read, old_read(fd, buf, count));
}

static long my_sysinfo(struct sysinfo __user *info)
{
    syscall_wrapper(__NR_sysinfo, old_sysinfo(info));
}

static long my_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user* addr, int addr_len)
{
    syscall_wrapper(__NR_sendto, old_sendto(fd, buff, len, flags, addr, addr_len));
}

static long my_socket(int family, int type, int protocol)
{
    syscall_wrapper(__NR_socket, old_socket(family, type, protocol));
}

static long my_unlink(const char __user *pathname)
{
    syscall_wrapper(__NR_unlink, old_unlink(pathname));
}

static long my_wait4(pid_t upid, int __user * stat_addr, int options, struct rusage __user* ru)
{
    syscall_wrapper(__NR_wait4, old_wait4(upid, stat_addr, options, ru));
}

static long my_utime(char __user *filename, struct utimbuf __user *times)
{
    syscall_wrapper(__NR_utime, old_utime(filename, times));
}

static long my_umask(int mask)
{
    syscall_wrapper(__NR_umask, old_umask(mask));
}

static long my_uname(struct old_utsname __user *name)
{
    syscall_wrapper(__NR_uname, old_uname(name));
}

static long my_stat(const char __user* filename, struct __old_kernel_stat __user* statbuf)
{
    syscall_wrapper(__NR_stat, old_stat(filename, statbuf));
}

static long my_nanosleep(const struct timespec* reg, struct timespec* rem)
{
    syscall_wrapper(__NR_nanosleep, old_nanosleep(reg, rem));
}

static long my_setpgid(pid_t pid, pid_t pgid)
{
    syscall_wrapper(__NR_setpgid, old_setpgid(pid, pgid));
}

static long my_readlink(const char __user *path, char __user *buf, int bufsiz)
{
    syscall_wrapper(__NR_readlink, old_readlink(path, buf, bufsiz));
}
//this function store the replaced syscall entry into shadow_table
//and replace the syscall_table with our wrapping functions
//
static void replace_table(void)
{

    /* 
       shadow_table[__NR_chdir] = syscall_table[__NR_chdir];
       syscall_table[__NR_chdir] = my_chdir;

       shadow_table[__NR_chmod] = syscall_table[__NR_chmod];
       syscall_table[__NR_chmod] = my_chmod;
       */


    old_brk           = syscall_table[__NR_brk];
    old_chdir         = syscall_table[__NR_chdir];
    old_chmod         = syscall_table[__NR_chmod];
    old_clock_gettime = syscall_table[__NR_clock_gettime];
    old_close         = syscall_table[__NR_close];
    old_dup           = syscall_table[__NR_dup];
    old_dup2          = syscall_table[__NR_dup2];
    //old_execve        = syscall_table[__NR_execve];
    old_faccessat     = syscall_table[__NR_faccessat];
    old_fchmod        = syscall_table[__NR_fchmod];
    old_fchown        = syscall_table[__NR_fchown];
    old_fstat         = syscall_table[__NR_fstat];
    //old_futex         = syscall_table[__NR_futex];
    old_getcwd        = syscall_table[__NR_getcwd];
    old_getdents64    = syscall_table[__NR_getdents64];
    old_getgid        = syscall_table[__NR_getgid];
    old_getpid        = syscall_table[__NR_getpid];
    old_getppid       = syscall_table[__NR_getppid];
    old_ioctl         = syscall_table[__NR_ioctl];
    //old_kill          = syscall_table[__NR_kill];
    old_lseek         = syscall_table[__NR_lseek];
    old_lstat         = syscall_table[__NR_lstat];
    old_mkdir         = syscall_table[__NR_mkdir];
    //old_mmap          = syscall_table[__NR_mmap];
    old_write         = syscall_table[__NR_write];
    old_mprotect      = syscall_table[__NR_mprotect];
    old_read          = syscall_table[__NR_read];
    old_sysinfo       = syscall_table[__NR_sysinfo];
    old_sendto        = syscall_table[__NR_sendto];
    old_socket        = syscall_table[__NR_socket];
    old_unlink        = syscall_table[__NR_unlink];
    //old_wait4         = syscall_table[__NR_wait4];
    old_utime         = syscall_table[__NR_utime];
    old_umask         = syscall_table[__NR_umask];
    old_uname         = syscall_table[__NR_uname];
    old_stat          = syscall_table[__NR_stat];
    //old_nanosleep     = syscall_table[__NR_nanosleep];
    old_setpgid       = syscall_table[__NR_setpgid];
    old_readlink      = syscall_table[__NR_readlink];
    /*
    */

    fixed_set_memory_rw = (void *) kallsyms_lookup_name("set_memory_rw");
    if (!fixed_set_memory_rw)
    {
        printk(KERN_INFO "unable to find set_memory_rw symbol\n");
        return ;
    }

    fixed_set_memory_ro = (void *) kallsyms_lookup_name("set_memory_ro");
    if (!fixed_set_memory_ro)
    {
        printk(KERN_INFO "unable to find set_memory_ro symbol\n");
        return ;
    }

    if (syscall_table != NULL){
        int ret;
        unsigned long addr;
        unsigned long old_cr0;
        old_cr0 = read_cr0();

        write_cr0(old_cr0 & ~CRO_WP);
        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        write_cr3(virt_to_phys(current->mm->pgd));

        if (ret)
        {
            printk(KERN_INFO "unable to set the memory rw at %16lX\n", PAGE_ALIGN(addr) - PAGE_SIZE);
            return ;
        }

        syscall_table[__NR_brk]           = my_brk;
        syscall_table[__NR_chdir]         = my_chdir;
        syscall_table[__NR_chmod]         = my_chmod;
        syscall_table[__NR_clock_gettime] = my_clock_gettime;
        syscall_table[__NR_close]         = my_close;
        syscall_table[__NR_dup]           = my_dup;
        syscall_table[__NR_dup2]          = my_dup2;
        //syscall_table[__NR_execve]        = my_execve;
        syscall_table[__NR_faccessat]     = my_faccessat;
        syscall_table[__NR_fchmod]        = my_fchmod;
        syscall_table[__NR_fchown]        = my_fchown;
        syscall_table[__NR_fstat]         = my_fstat;
        //syscall_table[__NR_futex]         = my_futex;
        syscall_table[__NR_getcwd]        = my_getcwd;
        syscall_table[__NR_getdents64]    = my_getdents64;
        syscall_table[__NR_getgid]        = my_getgid;
        syscall_table[__NR_getpid]        = my_getpid;
        syscall_table[__NR_getppid]       = my_getppid;
        syscall_table[__NR_ioctl]         = my_ioctl;
        //syscall_table[__NR_kill]          = my_kill;
        syscall_table[__NR_lseek]         = my_lseek;
        syscall_table[__NR_lstat]         = my_lstat;
        syscall_table[__NR_mkdir]         = my_mkdir;
        //syscall_table[__NR_mmap]          = my_mmap;
        syscall_table[__NR_write]         = my_write;
        syscall_table[__NR_mprotect]      = my_mprotect;
        syscall_table[__NR_read]          = my_read;
        syscall_table[__NR_sysinfo]       = my_sysinfo;
        syscall_table[__NR_sendto]        = my_sendto;
        syscall_table[__NR_socket]        = my_socket;
        syscall_table[__NR_unlink]        = my_unlink;
        //syscall_table[__NR_wait4]         = my_wait4;
        syscall_table[__NR_utime]         = my_utime;
        syscall_table[__NR_umask]         = my_umask;
        syscall_table[__NR_uname]         = my_uname;
        syscall_table[__NR_stat]          = my_stat;
        //syscall_table[__NR_nanosleep]     = my_nanosleep;
        syscall_table[__NR_setpgid]       = my_setpgid;
        syscall_table[__NR_readlink]      = my_readlink;
        /*
        */
    

        write_cr0(old_cr0);
        ret = fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        write_cr3(virt_to_phys(current->mm->pgd));
    }
    else
    {
        printk(KERN_INFO "replace_table cannot find the location of syscall_table\n");
    }
}


static int exit_syscall_table(void)
{
    //syscall_table[__NR_brk] = old_brk

    if (syscall_table != NULL)
    {
        int ret;
        unsigned long addr;

        write_cr0(read_cr0() & ~CRO_WP);
        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 1);

        if (ret)
        {
            printk(KERN_INFO "unable to set the memory rw at %16lX\n", PAGE_ALIGN(addr) - PAGE_SIZE);
            return 1;
        }

        syscall_table[__NR_brk]           = old_brk;
        syscall_table[__NR_chdir]         = old_chdir;
        syscall_table[__NR_chmod]         = old_chmod;
        syscall_table[__NR_clock_gettime] = old_clock_gettime;
        syscall_table[__NR_close]         = old_close;
        syscall_table[__NR_dup]           = old_dup;
        syscall_table[__NR_dup2]          = old_dup2;
        //syscall_table[__NR_execve]        = old_execve;
        syscall_table[__NR_faccessat]     = old_faccessat;
        syscall_table[__NR_fchmod]        = old_fchmod;
        syscall_table[__NR_fchown]        = old_fchown;
        syscall_table[__NR_fstat]         = old_fstat;
        //syscall_table[__NR_futex]         = old_futex;
        syscall_table[__NR_getcwd]        = old_getcwd;
        syscall_table[__NR_getdents64]    = old_getdents64;
        syscall_table[__NR_getgid]        = old_getgid;
        syscall_table[__NR_getpid]        = old_getpid;
        syscall_table[__NR_getppid]       = old_getppid;
        syscall_table[__NR_ioctl]         = old_ioctl;
        syscall_table[__NR_lseek]         = old_lseek;
        //syscall_table[__NR_kill]          = old_kill;
        syscall_table[__NR_lstat]         = old_lstat;
        syscall_table[__NR_mkdir]         = old_mkdir;
        //syscall_table[__NR_mmap]          = old_mmap;
        syscall_table[__NR_write]         = old_write;
        syscall_table[__NR_mprotect]      = old_mprotect;
        syscall_table[__NR_read]          = old_read;
        syscall_table[__NR_sysinfo]       = old_sysinfo;
        syscall_table[__NR_sendto]        = old_sendto;
        syscall_table[__NR_socket]        = old_socket;
        syscall_table[__NR_unlink]        = old_unlink;
        //syscall_table[__NR_wait4]         = old_wait4;
        syscall_table[__NR_utime]         = old_utime;
        syscall_table[__NR_umask]         = old_umask;
        syscall_table[__NR_uname]         = old_uname;
        syscall_table[__NR_stat]          = old_stat;
        //syscall_table[__NR_nanosleep]     = old_nanosleep;
        syscall_table[__NR_setpgid]       = old_setpgid; 
        syscall_table[__NR_readlink]      = old_readlink;
        /*
        */

        write_cr0(read_cr0() | CRO_WP);

        addr = (unsigned long) syscall_table;
        ret = fixed_set_memory_ro(PAGE_ALIGN(addr) - PAGE_SIZE, 1);
        //printk(KERN_INFO "sys_brk was restored\n");
    }

    return 0;
}

static int init_syscall_table(void)
{
    /* 
     * this function finds out the mem addr of syscall table,
     * then replace some entries of it with our wrapping function
     */

    printk(KERN_INFO "start to find syscall addr\n");
    syscall_table = (void**) find_syscall_table();
    printk(KERN_INFO "start to replace syscall addr\n");
    replace_table();
    syscall_task.status = 1;

    printk(KERN_INFO "init_syscall_table done\n");
    return 0;
}

static int init_cl_char_device(void)
{
    /*
     * this function create a character device file.
     * A user program can write to the character device file to inform this 
     * module which pid to intercept
     */

    //create character device file
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0){
        printk(KERN_INFO "CL failed to register a major number\n");
        return majorNumber;
    }

    //printk(KERN_INFO "CL registered with major number:%d\n", majorNumber);

    clcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(clcharClass)){                // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_INFO "Failed to register device class\n");
        return PTR_ERR(clcharClass);          // Correct way to return an error on a pointer
    }

    //printk(KERN_INFO "CL: device class registered correctly\n");

    // Register the device driver
    clcharDevice = device_create(clcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(clcharDevice)){               // Clean up if there is an error
        class_destroy(clcharClass);           // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(clcharDevice);
    }
    //printk(KERN_INFO "CL: device class created correctly\n"); // Made it! device was initialized
    pidFlag = 0;

    printk(KERN_INFO "init_cl_char_device done\n");
    return 0;
}

static int exit_cl_char_device(void)
{
    device_destroy(clcharClass, MKDEV(majorNumber, 0));     // remove the device
    class_unregister(clcharClass);                          // unregister the device class
    class_destroy(clcharClass);                             // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
    printk(KERN_INFO "CL: Goodbye from the LKM!\n");
    return 0;
}
static int init_worker_thread(void)
{
    /*
     * this function create & launch a kernel worker thread to perform syscalls
     * for process $targetPid
     */
    char worker_name[16] = "CL_worker";
    //create worker thread
    printk(KERN_INFO "create worker thread\n");
    worker_id = kthread_create(worker, NULL, worker_name);
    if ((worker_id))
    {
        printk(KERN_INFO "worker thread created");
        wake_up_process(worker_id);
    }

    printk(KERN_INFO "init_worker_thread done");
    return 0;
}

static int exit_worker_thread(void)
{
    return kthread_stop(worker_id);
}

/*
static int init_trivial(void)
{
    //printk(KERN_INFO "p addr of 0x0 is %x\n",iopa(0x0));
    iopa_ptr = (void*) kallsyms_lookup_name("iopa");
    if (!iopa_ptr){
        printk(KERN_INFO "[ERROR]:unable to find iopa");
        return 1;
    }
    printk(KERN_INFO "iopa found!!!!");
    unsigned long paddr, vaddr;
    vaddr = 0x0;
    paddr = virt_to_phys((void*)vaddr);
    printk(KERN_INFO "!!!!!!!!!!!!!%016lx!!!!!!!!!!!!!!!", paddr);
    return 0;
}
static void exit_trivial(void)
{
    iopa_ptr = NULL;
}
*/
static int __init cl_km_init(void)
{
    //init_trivial();
    init_syscall_table();
    init_cl_char_device();
    init_worker_thread();
    printk(KERN_INFO "cl_km_init returns\n");
    return 0;
}

static void __exit cl_km_exit(void)
{
    //exit_trivial();
    exit_syscall_table();
    exit_cl_char_device();
    exit_worker_thread();
    printk(KERN_INFO "cl_km_exit done");
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    long result = 0;
    pid_t pid;
    pid = *(pid_t*)buffer;
    
    //result = kstrtol(buffer, 0, &pid);
    //printk(KERN_INFO "result = %ld  pid = %ld\n", result, pid);
    //printk("input str:%s\n", buffer);
    if (pid >= 0){
        targetPid = pid;
        pidFlag = 1;
        printk(KERN_INFO "CL: pid %ld received\n", pid);
    }
    return len;
}

#ifndef CONFIG_X86_64
#error "Architectures other than x86_64 not currently supported"
#endif

module_init(cl_km_init);
module_exit(cl_km_exit);
