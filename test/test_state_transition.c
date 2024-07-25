#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3
#define INVALID_STATE 4

int main(int argc, char *argv[]){
    char passwd[128] = "1234";
    int sys0 = 134;

    printf("Calling syscall with code %d on state ON\n", sys0);
	syscall(sys0, ON, passwd);		

    printf("Calling syscall with code %d on state OFF\n", sys0);
    syscall(sys0, OFF, passwd);

    printf("Calling syscall with code %d on state REC_ON\n", sys0);
    syscall(sys0, REC_ON, passwd);

    printf("Calling syscall with code %d on state REC_OFF\n", sys0);
    syscall(sys0, REC_OFF, passwd);

    printf("Calling syscall with code %d on state INVALID_STATE\n", sys0);
    syscall(sys0, INVALID_STATE, passwd);
    
	return 0;
}