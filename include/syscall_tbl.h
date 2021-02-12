#ifndef __STBL_H__
#define __STBL_H__
#define CRO_WP 0x00010000
#define SET_TBL_ENT(sysname)\
({\
    if ((syslist & __BN_##sysname) > 0){\
        old_##sysname = syscall_table[__NR_##sysname];\
        syscall_table[__NR_##sysname] = my_##sysname;\
    }\
})

#define RESET_TBL_ENT(sysname)\
({\
    if ((last_syslist & __BN_##sysname) > 0){\
        syscall_table[__NR_##sysname] = old_##sysname;\
    }\
})

extern void** syscall_table;
extern int            pidFlag;              //0:pid unset 1:pid set
extern struct task_struct* task;
void replace_table(unsigned long syslist);
int restore_syscall_table(void);
int init_syscall_table(void);
unsigned long** find_syscall_table(void);
extern int (*fixed_set_memory_rw)(unsigned long, int);
extern int (*fixed_set_memory_ro)(unsigned long, int);

struct syscall_args{
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
    const struct cred __rcu* cred;
    const struct cred __rcu* real_cred;
    struct nsproxy* nsproxy;
    struct task_struct* group_leader;
    struct task_struct __rcu *real_parent;
    unsigned int personality;
    struct audit_context* audit_context;
    //struct sighand_struct* sighand;
    //struct signal_struct* signal;

};
extern struct syscall_args syscall_task;
#endif
