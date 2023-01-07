#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>


//test program for libseccomp.  This test program was insipired by several on the internet for wh//licensing allows for this type of use.  Please note that some of those tutorial programs
//won't work as written, since, on some architectures at least, the fstat system call has 
//been replaced with newfstatat.  This program makes that adjustment.

//What does this test?  This program tests a successful response to the system calls involved in //the C fprintf call.  See comments below aoubt the filter setup.  


//Need help understanding what system calls would cause the program to exit with a kill?  Use
//the strace command.  Eg., strace ./a.out

scmp_filter_ctx ctx;	//define data structure to hold the filter
			

/* clean up function- a way to clean up seccomp context prior to exiting */

void cleanup(int rtnCode)
{
	seccomp_release(ctx);
	exit(rtnCode);
}

//function to set up our desired filter.  In this case, we want to 
//allow our program to write to stdout, and to exit via exitgroup. 
//We also want to allow fstatat.  Running strace shows us that fprintf will
//issue an fstatat system call, so we want to allow that.  We also want to allow
//exitgroup by default, for exiting.
//

void setup_allow_fprintf()
{
	int rtnCode;

	//initialize the filter for an allow list approach. This means that, by 	//default, all syscalls not in the allow list will cause this program to 	//terminate.
	//
	

	//initialize the context.  ctx is a pointer and should not be null if 
	//the operation is successful.  The default action to be taken is to kil	//the process unless there is a filter allowing the sys call
	 
      	if ((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL) { 
		cleanup(1);
	}
	// now reset... this is just good practice and not strictly necessary
	// in this case.  See man page for libseccomp
	
	if ((rtnCode = seccomp_reset(ctx, SCMP_ACT_KILL)) != 0) { //returns 0 upon success

	
		cleanup(1);
	}

	//now add the allowed system calls, as described in the initial comments
	
	if ((rtnCode = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat),0)) != 0) {
		cleanup(1);
	}

	if ((rtnCode = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write),0)) != 0) {
                cleanup(1);
        }

	if ((rtnCode = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group),0)) != 0) {
                cleanup(1);
        }

	//now load the filter for the current context into the kernel
	
	if ((rtnCode = seccomp_load(ctx)) !=0) {
		cleanup(1);
	}
}	

//main program

int main() {

	setup_allow_fprintf();

	//let it roll! 
	
	fprintf(stdout,"Hi there!\n");
	cleanup (0);  //if we got here, we know everything worked


}
	
