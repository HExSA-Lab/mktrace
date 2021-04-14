[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# mktrace 
`mktrace` is a system call delegation tool is designed to emulate system call forwarding, a technique used in multi-kernels (Intel mOS, IHK/ Mckernel) to delegate unsupported system calls in specialized operating systems to a general-purpose
OS. 

The idea is that given some workload, a user can estimate system call forwarding
overheads *without* actually porting their application to a multi-kernel.

mktrace is currently only supported for Linux. It intercepts selected system calls and delegates them to a kernel thread which then introduces an
artificial delay and emulates the syscall execution.

## Supported OS/kernel

`mktrace` has been verified to work on the following configuration:

- CentOS 7
- Linux kernel version 3.10.1062


## Prerequisites

- GNU Make
- gcc
- Kernel devel headers 


## Building

```sh
[you@machine] make 
[you@machine] sudo insmod mktraced.ko 
```

You can verify that `mktrace` was set up properly be looking at the kernel
logs (run `dmesg`).

## Usage

```sh
[you@machine] ./mktrace <application>
```

### Examples

A standard usage of this tool requires explicitly specifiying a system call profile (`mktrace_pf`). This file contains the system calls which are to be delegated. 

Example

```sh
[you@machine] ./mktrace /usr/bin/ls
```

The input file format for `mktrace_pf` is as follows, using
the standard Linux system call names from the kernel headers.

```
write
brk
...
```

### Limitations 

Any system call which tries to modify the task struct such as `arch_prctl`,
`execve`, etc. are currently not supported by design. For more information
on which system calls are supported by `mktrace` see the
`supported_system_calls` file.
