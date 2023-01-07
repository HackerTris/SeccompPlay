#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>


//test program for libseccomp.  This test program was insipired by several on the internet for wh//licensing allows for this type of use.  Please note that some of those tutorial programs
//won't work as written, since, on some architectures at least, the fstat system call has 
//been replaced with newfstatat.  This program makes that adjustment.


//What does this test?  This program tests a "bad" response when the program tries to read the sy//system's password file.  The read system call is not inluded in the filter, so this should fail//

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

	/* only syscalls involved in fprintf write are being allowed.  This includes newfstatat, 
	   write, and exit_group.  Reading of any file is not permitted by the filter */

	FILE *fd;

	setup_allow_fprintf(); 

	//let it roll! 
	
	// let us see if we can read the password file!
	
	printf("hello.  Getting ready to read the password file, which should cause this program to crash! \n");


	//note:  when testing, you can comment out the seccomp lib calls and just make sure you c
	//an read the file.  You will get a permission denied unless you run under sudo.
	//If not sudo and you get permission denied, then that is not the same thing as receiving
	//a kill signal, which should happen when filters are applied.  Test running as sudo if 
	//you want to eliminate that condition.  Running as sudo will still cause the failure
	//since the write system call is not allowed. 
	
	if ((fd=fopen("/etc/shadow", "r"))==NULL) {
		perror("fopen");
		cleanup(1);
	}
	cleanup (0);  //if we got here, we know everything worked


}
	
