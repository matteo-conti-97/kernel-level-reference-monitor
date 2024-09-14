#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "../reference-monitor/error_codes.h"


int sys_change_passwd = 177;


int main(int argc, char *argv[]){
    char *old_passwd;
    char *new_passwd;

    //Get password and state from parameters
    if(argc < 3){
        printf("Usage: %s <new_password> <old_passwd>\n", argv[0]);
        return -1;
    }
    new_passwd = (char *)malloc(strlen(argv[1]) + 1);
    old_passwd = (char *)malloc(strlen(argv[2]) + 1);

    strcpy(new_passwd, argv[1]);
    strcpy(old_passwd, argv[2]);
    
    syscall(sys_change_passwd, new_passwd, old_passwd);
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