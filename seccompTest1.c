#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>

int main()
{
    /* note:  the prctl system call will perorm an "operation" on the current process.  IN this case, it sets the "seccomp" mode, and uses the strict mode.  The 
    strict mode will only allow the process to read, write, and exit.  But not exit_group.  In effect, this setting will casue this program to always receive a kill
    signal since we are trying to print and/or trying to do an exit_group
    */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)  !=0){ 
        perror("prctl");
        return 1;
    }
    printf("hello world\n");
    return 0;
    
}