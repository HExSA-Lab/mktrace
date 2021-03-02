#ifndef __WORKER_H__
#define __WORKER_H__
#define START_DELEGATEE 0
#define PAUSE_DELEGATEE 1
int init_worker_thread(void);
int exit_worker_thread(void);
extern struct task_struct* worker_id;
#endif
