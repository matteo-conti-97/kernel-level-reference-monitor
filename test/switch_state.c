#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../reference-monitor/states.h"
#include "../reference-monitor/error_codes.h"


int sys_switch = 134;


int main(int argc, char *argv[]){
    char passwd[128] = "1234";
    int state = atoi(argv[1]);
    switch(state){
        case ON:
            printf("Switching to ON\n");
            break;
        case OFF:
            printf("Switching to OFF\n");
            break;
        case REC_ON:
            printf("Switching to REC_ON\n");
            break;
        case REC_OFF:
            printf("Switching to REC_OFF\n");
            break;
        default:
            printf("Unknown state\n");
            break;
    }
    syscall(sys_switch, state, passwd);
    switch(errno){
        case SUCCESS:
            printf("Success\n");
            break;
        case -GENERIC_ERR:
            printf("Error: GENERIC_ERR\n");
            break;
        case -OP_NOT_PERMITTED_ERR:
            printf("Error: OP_NOT_PERMITTED_ERR\n");
            break;
        case -PASSWD_MISMATCH_ERR:
            printf("Error: PASSWD_MISMATCH_ERR\n");
            break;
        case -RES_NOT_PROTECTED_ERR:
            printf("Error: RES_NOT_PROTECTED_ERR\n");
            break;
        case -INVALID_STATE_ERR:
            printf("Error: INVALID_STATE_ERR\n");
            break;
    }
	return 0;
}