#ifndef __HANDLER_H__
#define __HANDLER_H__

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
    const struct cred __rcu* old_cred;\
    const struct cred __rcu* old_real_cred;\
    old_mm = current->mm;\
    old_active_mm = current->active_mm;\
    old_files = current->files;\
    old_fs = current->fs;\
    old_nsproxy = current->nsproxy;\
    old_group_leader = current->group_leader;\
    old_real_parent = current->real_parent;\
    old_personality = current->personality;\
    old_audit_context = current->audit_context;\
    old_cr3 = read_cr3();\
    old_cred = current->cred;\
    old_real_cred = current->real_cred;\
    task_lock(current);\
    current->files = syscall_task.files;\
    current->fs = syscall_task.fs;\
    current->nsproxy = syscall_task.nsproxy;\
    current->group_leader = syscall_task.group_leader;\
    rcu_assign_pointer(current->real_parent, syscall_task.real_parent);\
    rcu_assign_pointer(current->cred, syscall_task.cred);\
    rcu_assign_pointer(current->real_cred, syscall_task.real_cred);\
    current->personality = syscall_task.personality;\
    current->audit_context = syscall_task.audit_context;\
    atomic_inc(&current->active_mm->mm_count);  /*Hack To avoid mmdrop in use_mm*/ \
    task_unlock(current);\
    unuse_mm(current->active_mm);\
    use_mm(syscall_task.active_mm);\
    __flush_tlb_all();\


#define HANDLE_BOT  \
    task_lock(current);\
    current->files = old_files;\
    current->fs = old_fs;\
    current->nsproxy = old_nsproxy;\
    current->group_leader = old_group_leader;\
    rcu_assign_pointer(current->real_parent, old_real_parent);\
    rcu_assign_pointer(current->cred, old_cred);\
    rcu_assign_pointer(current->real_cred, old_real_cred);\
    current->personality = old_personality;\
    current->audit_context = old_audit_context;\
    task_unlock(current);\
    atomic_dec(&old_active_mm->mm_count);\
    unuse_mm(current->active_mm);\
    use_mm(old_active_mm);\
    syscall_task.status = 1;\
    __flush_tlb_all();\
    wmb();\
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

#endif
