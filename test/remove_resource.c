#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../reference-monitor/error_codes.h"


int sys_rm = 174;


void check_rm(char *path, char *passwd){
    long res = syscall(sys_rm, path, passwd);
    switch(errno){
        case SUCCESS:
            printf("Resource removed successfully\n");
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
        case -RES_NOT_PROTECTED_ERR:
            printf("Resource not protected\n");
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
    char *path;

    if(argc < 3){
        printf("Usage: %s <path> <password>\n", argv[0]);
        return -1;
    }

    path = malloc(strlen(argv[1]) + 1);
    strcpy(path, argv[1]);
    passwd = malloc(strlen(argv[2]) + 1);
    strcpy(passwd, argv[2]);

    printf("Removing resource %s\n", path);

    check_rm(path, passwd);

	return 0;
}