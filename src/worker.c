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
#include "../include/worker.h"
#include "../include/handler.h"
#include "../include/old_syscalls.h"
#include "../include/syscall_tbl.h"

struct task_struct* worker_id;
struct completion comp;
DECLARE_COMPLETION(comp);

int worker(void* data){
	printk("worker launched\n");
	while(!kthread_should_stop())
	{
		wait_event_interruptible(wait_queue_delegate, 
			    syscall_task.status != PAUSE_DELEGATEE);
		if (syscall_task.status == START_DELEGATEE){
			switch(syscall_task.call_num)
			{

				case __NR_brk:
					{
						HANDLE_CALL1(old_brk, unsigned long);
					}
				case __NR_chdir:
					{
						HANDLE_CALL1(old_chdir, const char*);
					}
				case __NR_chmod:
					{
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
				case __NR_faccessat:
					{
						HANDLE_CALL3(old_faccessat, int, const char*, int);
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
						HANDLE_CALL2(old_fstat, int, struct __old_kernel_stat*);
					}
				case __NR_fcntl:
					{
						HANDLE_CALL3(old_fcntl, int, int, unsigned long);
					}
				case __NR_futex:
					{
						HANDLE_CALL6(old_futex, u32*, int, u32, struct timespec*, u32*, u32);
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

						HANDLE_CALL0(old_getgid);
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
				case __NR_munmap:
					{
						HANDLE_CALL2(old_munmap, unsigned long, unsigned long);
					}
				case __NR_write:
					{
						HANDLE_CALL3(old_write, unsigned int, char*, size_t);
					}
				case __NR_open:
					{
						HANDLE_CALL3(old_open, char*, int, mode_t);
					}
				case __NR_access:
					{
						HANDLE_CALL2(old_access, char*, int);
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
        	wake_up_all(&wait_queue_delegate);
	}	
    complete(&comp);
	return 0;
}


int init_worker_thread(void)
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


int exit_worker_thread(void)
{
    syscall_task.status = 2;
    
    kthread_stop(worker_id);

    wake_up_all(&wait_queue_delegate);
    wait_for_completion(&comp);
    return 0;
}

