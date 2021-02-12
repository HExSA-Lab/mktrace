#ifndef __DEVICE_H__
#define __DEVICE_H__

int init_cl_char_device(void);
int exit_cl_char_device(void);
ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset);

#endif
