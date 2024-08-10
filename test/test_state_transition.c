#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../reference-monitor/error_codes.h"
#include "../reference-monitor/states.h"

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
    char *passwd;

    //Get password from parameters
    if(argc < 2){
        printf("Usage: %s <password>\n", argv[0]);
        return -1;
    }
    passwd = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(passwd, argv[1]);

    check_switch(ON, passwd);
    check_switch(OFF, passwd);
    check_switch(REC_ON, passwd);
    check_switch(REC_OFF, passwd);
    check_switch(50, passwd);
	return 0;
}