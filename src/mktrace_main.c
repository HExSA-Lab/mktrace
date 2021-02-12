#include <linux/module.h>
#include "../include/worker.h"
#include "../include/device.h"
#include "../include/syscall_tbl.h"


MODULE_AUTHOR("Conghao Liu <cliu115@hawk.iit.edu>, Brian Richard Tauro <btauro@hawk.iit.edu>");
MODULE_DESCRIPTION("Syscall delegation");
MODULE_LICENSE("GPL");
MODULE_VERSION("0,1");

static int __init cl_km_init(void)
{
    init_syscall_table();
    init_cl_char_device();
    init_worker_thread();
    printk(KERN_INFO "cl_km_init returns\n");
    return 0;
}

static void __exit cl_km_exit(void)
{
    restore_syscall_table();
    exit_cl_char_device();
    exit_worker_thread();
    printk(KERN_INFO "cl_km_exit done");
}


#ifndef CONFIG_X86_64
#error "Architectures other than x86_64 not currently supported"
#endif

module_init(cl_km_init);
module_exit(cl_km_exit);
