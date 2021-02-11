#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>

#include "bitnum.h"


// TODO: use optparse
// TODO: current bitmap approach can't support more than 64 intercepted system calls

#define INFO(fmt, args...)  printf("[MKTRACE]" fmt, ##args)
#define DEBUG(fmt, args...) printf("[MKTRACE]" fmt, ##args)
#define ERROR(fmt, args...) fprintf(stderr, "[MKTRACE]" fmt, ##args)

//pid_t:4 + unsigned long:8 = 12
#define MSG_LEN 12  
//character device file name
#define CDF_NAME "/dev/cl_sf"

// TODO: Make this a -f option
#define PF_NAME "mktrace_pf"
#define LINE_BUF_SIZE 1024

static int get_syslist (unsigned long * slist)
{
    FILE* fp;
    char* lineBuf;
    size_t lineMaxLen;
    ssize_t lineLen;

    if (!slist) {
        ERROR("No system call bitmap provided\n");
        return -1;
    }

    lineBuf = (char*) malloc(LINE_BUF_SIZE);
    bzero(lineBuf, LINE_BUF_SIZE);

    lineMaxLen = LINE_BUF_SIZE;
    lineLen = 0;

    // open mktrace profile
    fp = fopen(PF_NAME, "r");
    if (fp == NULL){
        ERROR("cannot open syscall interception profile: %s\n", PF_NAME);
        return  -1;
    }

    //get syscall list from the profile
    while((lineLen = getline(&lineBuf, &lineMaxLen, fp)) != -1){

        //rm newline char from the str
        if (lineLen >= 1){
            if (lineBuf[lineLen - 1] == '\n'){
                lineBuf[lineLen - 1] = 0;
            }
        }
        /*
        printf("%d\n", strlen(lineBuf));
        char buf[] = "brk";
        printf("%d\n", strcmp(buf, lineBuf));
        */

        if (strcmp("brk", lineBuf) == 0){
            *slist |= __BN_brk;
            continue;
        }
        if (strcmp("chdir", lineBuf) == 0){
            *slist |= __BN_chdir;
            continue;
        }
        if (strcmp("chmod", lineBuf) == 0){
            *slist |= __BN_chmod;
            continue;
        }
        if (strcmp("clock_gettime", lineBuf) == 0){
            *slist |= __BN_clock_gettime;
            continue;
        }
        if (strcmp("close", lineBuf) == 0){
            *slist |= __BN_close;
            continue;
        }
        if (strcmp("dup", lineBuf) == 0){
            *slist |= __BN_dup;
            continue;
        }
        if (strcmp("dup2", lineBuf) == 0){
            *slist |= __BN_dup2;
            continue;
        }
        if (strcmp("faccessat", lineBuf) == 0){
            *slist |= __BN_faccessat;
            continue;
        }
        if (strcmp("fchmod", lineBuf) == 0){
            *slist |= __BN_fchmod;
            continue;
        }
        if (strcmp("fchown", lineBuf) == 0){
            *slist |= __BN_fchown;
            continue;
        }
        if (strcmp("fstat", lineBuf) == 0){
            *slist |= __BN_fstat;
            continue;
        }
        if (strcmp("futex", lineBuf) == 0){
            *slist |= __BN_futex;
            continue;
        }
        if (strcmp("getcwd", lineBuf) == 0){
            *slist |= __BN_getcwd;
            continue;
        }
        if (strcmp("getdents64", lineBuf) == 0){
            *slist |= __BN_getdents64;
            continue;
        }
        if (strcmp("getgid", lineBuf) == 0){
            *slist |= __BN_getgid;
            continue;
        }
        if (strcmp("getpid", lineBuf) == 0){
            *slist |= __BN_getpid;
            continue;
        }
        if (strcmp("getppid", lineBuf) == 0){
            *slist |= __BN_getppid;
            continue;
        }
        if (strcmp("ioctl", lineBuf) == 0){
            *slist |= __BN_ioctl;
            continue;
        }
        if (strcmp("lseek", lineBuf) == 0){
            *slist |= __BN_lseek;
            continue;
        }
        if (strcmp("lstat", lineBuf) == 0){
            *slist |= __BN_lstat;
            continue;
        }
        if (strcmp("mkdir", lineBuf) == 0){
            *slist |= __BN_mkdir;
            continue;
        }
        if (strcmp("mprotect", lineBuf) == 0){
            *slist |= __BN_mprotect;
            continue;
        }
        if (strcmp("read", lineBuf) == 0){
            *slist |= __BN_read;
            continue;
        }
        if (strcmp("readlink", lineBuf) == 0){
            *slist |= __BN_readlink;
            continue;
        }
        if (strcmp("sendto", lineBuf) == 0){
            *slist |= __BN_sendto;
            continue;
        }
        if (strcmp("setpgid", lineBuf) == 0){
            *slist |= __BN_setpgid;
            continue;
        }
        if (strcmp("socket", lineBuf) == 0){
            *slist |= __BN_socket;
            continue;
        }
        if (strcmp("stat", lineBuf) == 0){
            *slist |= __BN_stat;
            continue;
        }
        if (strcmp("sysinfo", lineBuf) == 0){
            *slist |= __BN_sysinfo;
            continue;
        }
        if (strcmp("umask", lineBuf) == 0){
            *slist |= __BN_umask;
            continue;
        }
        if (strcmp("uname", lineBuf) == 0){
            *slist |= __BN_uname;
            continue;
        }
        if (strcmp("unlink", lineBuf) == 0){
            *slist |= __BN_unlink;
            continue;
        }
        if (strcmp("utime", lineBuf) == 0){
            *slist |= __BN_utime;
            continue;
        }
        if (strcmp("wait4", lineBuf) == 0){
            *slist |= __BN_wait4;
            continue;
        }
        if (strcmp("write", lineBuf) == 0){
            *slist |= __BN_write;
            continue;
        }
        if (strcmp("mmap", lineBuf) == 0){
            *slist |= __BN_mmap;
            continue;
        }
        if (strcmp("munmap", lineBuf) == 0){
            *slist |= __BN_munmap;
            continue;
        }
        if (strcmp("access", lineBuf) == 0){
            *slist |= __BN_access;
            continue;
        }
        if (strcmp("open", lineBuf) == 0){
            *slist |= __BN_open;
            continue;
        }
        if (strcmp("fcntl", lineBuf) == 0){
            *slist |= __BN_fcntl;
            continue;
        }
    }

    fclose(fp);
    free(lineBuf);
    return 0;
}



static void __attribute__((noreturn)) usage (char ** argv) 
{
    fprintf(stderr, "Usage: %s <program>\n", argv[0]);
    exit(EXIT_SUCCESS);
}


int main(int argc, char** argv)
{
    pid_t childPid;
    int fd;
    int ret;

    if (argc < 2){
        usage(argv);
    }

    if (access(argv[1], F_OK) != 0){
        ERROR("executable %s does not exist (please provide full path)\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    childPid = fork();

    if (childPid == 0){
        //this is child process

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], &argv[1]);

        //error happens if we are here
        ERROR("execv failed");
        exit(EXIT_FAILURE);
    }
    else{
        // parent process
        char pidStr[MSG_LEN];
        bzero(pidStr, MSG_LEN);
        memcpy(pidStr, &childPid, sizeof(pid_t));
        unsigned long syslist = 0;
        if (get_syslist(&syslist) != 0) {
            ERROR("Could not create system call profile\n");
            exit(EXIT_FAILURE);
        }
        memcpy(pidStr + 4, &syslist, sizeof(syslist));
        //sprintf(pidStr, "%d", childPid);
        //sprintf(pidStr, "%d", 95277);

        //open the device file
        fd = open(CDF_NAME, O_RDWR);
        if (fd < 0){
            ERROR("failed to open device file %s", CDF_NAME);
            wait(NULL);
            exit(EXIT_FAILURE);
        }

        //send the pid and syslist
        ret = write(fd, pidStr, MSG_LEN);
        //ret = write(fd, pidStr, strlen(pidStr));
        if (ret < 0){
            ERROR("failed to write message to %s", CDF_NAME);
            wait(NULL);
            exit(EXIT_FAILURE);
        }

        close(fd);

        //resume the child
        wait(NULL);
        ptrace(PTRACE_DETACH, childPid, NULL, NULL);
    }
    
    //wait until child process terminates
    wait(NULL);
    return 0;
}
