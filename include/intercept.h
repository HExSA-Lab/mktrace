#ifndef __INTERPRET_H_
#define __INTERPRET_H_

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
extern pid_t          targetPid;
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
        while(!syscall_task.status) wake_up_process(worker_id);\
        result = syscall_task.ret;\
   }\
    else{\
        result = old_call;\
    }\
    return result;\
})

#endif
