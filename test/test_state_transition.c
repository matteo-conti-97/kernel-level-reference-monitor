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

//Error codes
#define SUCCESS 0
#define GENERIC_ERR -1 
#define OP_NOT_PERMITTED_ERR -2
#define PASSWD_MISMATCH_ERR -3
#define INVALID_STATE_ERR -5

int sys_switch = 134;

int check_switch(int state, char *passwd){
    long res = syscall(sys_switch, state, passwd);
    switch(errno){
        case SUCCESS:
            printf("Success\n");
            break;
        case -GENERIC_ERR:
            printf("Generic error\n");
            break;
        case -OP_NOT_PERMITTED_ERR:
            printf("Operation not permitted\n");
            break;
        case -PASSWD_MISMATCH_ERR:
            printf("Password mismatch\n");
            break;
        case -INVALID_STATE_ERR:
            printf("Invalid state\n");
            break;
        default:
            printf("Unknown error\n");
            break;
    }
}

int main(int argc, char *argv[]){
    char passwd[128] = "1234";
    check_switch(ON, passwd);
    check_switch(OFF, passwd);
    check_switch(REC_ON, passwd);
    check_switch(REC_OFF, passwd);
    check_switch(INVALID_STATE, passwd);
	return 0;
}