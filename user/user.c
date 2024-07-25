#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>


int main(int argc, char *argv[]){
    char passwd[128] = "1234";
    char buff[128][128];
    int sys0 = 134, sys1 = 156, sys2 = 174, sys3 = 177;
    printf("Calling syscall with code %d\n", sys0);
	syscall(sys0, 0, passwd);	

    printf("Calling syscall with code %d\n", sys1);
	syscall(sys1, passwd, passwd);	

    printf("Calling syscall with code %d\n", sys2);
	syscall(sys2, passwd, passwd);	

    printf("Calling syscall with code %d\n", sys3);
	syscall(sys3, buff);	

	return 0;
}