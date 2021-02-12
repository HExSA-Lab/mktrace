#ifndef __WORKER_H__
#define __WORKER_H__
int init_worker_thread(void);
int exit_worker_thread(void);
extern struct task_struct* worker_id;
#endif
