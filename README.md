
# mktrace 

This tool intercepts selected system calls and delegates them to a kernel thread which then executes the sysem call.

## Prerequisites

* Linux kernel version  3.10.1062
  kernel headers

## Building

```sh
$ make 
$ sudo insmod mktraced.ko //insert kernel module
```

## Usage

```
$ ./mktrace <application>

Usage: sudo ./mktrace <application>

```

### Examples

A standard usage of this tool involves explicitly specifiying mktrace\_pf file which contains the system calls which needs to be delegated. The invocation
```
$ ./mktrace /usr/bin/ls
```

The input file format for mktrace\_pf is as follows:

```
write
brk
```
