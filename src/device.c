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
#include "../include/syscall_tbl.h"
#include "../include/device.h"
#define DEVICE_NAME "cl_sf"
#define CLASS_NAME  "cl"
//this contains the replaced syscall entry

static int            majorNumber;
static struct class*  clcharClass  = NULL;
static struct device* clcharDevice = NULL;
int            pidFlag;              //0:pid unset 1:pid set
pid_t          targetPid;
struct file_operations fops = {
    .write = dev_write,
};

int init_cl_char_device(void)
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

    clcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(clcharClass)){                // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_INFO "Failed to register device class\n");
        return PTR_ERR(clcharClass);          // Correct way to return an error on a pointer
    }

    // Register the device driver
    clcharDevice = device_create(clcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(clcharDevice)){               // Clean up if there is an error
        class_destroy(clcharClass);           // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(clcharDevice);
    }
    pidFlag = 0;

    printk(KERN_INFO "init_cl_char_device done\n");
    return 0;
}

int exit_cl_char_device(void)
{
    device_destroy(clcharClass, MKDEV(majorNumber, 0));     // remove the device
    class_unregister(clcharClass);                          // unregister the device class
    class_destroy(clcharClass);                             // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
    return 0;
}
/* 
 * Input format:
 * [PID] (4 bytes)
 * [SYSBITMAP] (8 bytes)
 */
ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset){
    pid_t pid;
    char buf[12];
    unsigned long syslist;

    if(copy_from_user(buf, buffer, len)){
	printk(KERN_ERR "[dev_write] failed to copy data from buffer\n");
    }
    *offset += len;
    pid = *(pid_t*)buf;
    syslist = *(unsigned long*)(buf + sizeof(pid_t));


    if (pid >= 0){
        //replace syscall_table 
        restore_syscall_table();
        replace_table(syslist);

        targetPid = pid;
        pidFlag = 1;
        printk(KERN_INFO "CL: pid %d received\n", pid);
    }
    return len;
}
