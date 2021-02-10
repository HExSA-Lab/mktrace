
# mktrace 
mktrace is a system call delegation tool built for Linux which is designed to emulate system call forwaring, a technique used in multi kernels like Intel mOS, IHK/ Mckernel, etc to delegate unsupported system calls to Linux.

This tool intercepts selected system calls and delegates them to a kernel thread which then executes the system call.

## Supported OS/kernel

* centos 7
* Linux kernel version 3.10.1062
* kernel headers

## Building

```sh
$ make 
$ sudo insmod mktraced.ko //insert kernel module
```

## Usage

```
$ ./mktrace <application>

Usage: ./mktrace <application>

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
