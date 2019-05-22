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

#define INFO(fmt, args...)  printf("[TRACER]" fmt "\n", ##args)
#define DEBUG(fmt, args...) printf("[TRACER]" fmt "\n", ##args)

#define MSG_LEN 64
//character device file name
#define CDF_NAME "/dev/cl_sf"

int main(int argc, char** argv)
{
    pid_t childPid;
    int fd;
    int ret;

    if (argc < 2){
        INFO("executable path missing!\ne.g.:\"./tracer ./a.out");
        return 0;
    }

    if (access(argv[1], F_OK) != 0){
        INFO("executable %s does not exist", argv[1]);
        return 0;
    }

    childPid = fork();

    if (childPid == 0){
        //this is child process

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], &argv[1]);

        //error happens if we are here
        INFO("execv failed");
        return 0;
    }
    else{
        //parent process
        /*
        */
        char pidStr[MSG_LEN];
        bzero(pidStr, MSG_LEN);
        sprintf(pidStr, "%d", childPid);
        //sprintf(pidStr, "%d", 95277);

        //open the device file
        fd = open(CDF_NAME, O_RDWR);
        if (fd < 0){
            INFO("failed to open device file %s", CDF_NAME);
            wait(NULL);
            return 0;
        }

        //send the pid
        ret = write(fd, pidStr, strlen(pidStr));
        if (ret < 0){
            INFO("failed to write message to %s", CDF_NAME);
            wait(NULL);
            return 0;
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
