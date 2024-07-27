#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <../reference-monitor/error_codes.h>


int sys_add = 156, sys_rm = 174;

void check_add(char *path, char *passwd){
    long res = syscall(sys_add, path, passwd);
    switch(errno){
        case SUCCESS:
            printf("Resource added successfully\n");
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
    char passwd[128] = "1234";
    char path[128] = "/home/matteo/ref_mon_test/test_file";

    //Call add with correct parameters
    printf("Calling sys_add\n");
    check_add(path, passwd);

    //Call add with same parameter to insert to copies
    printf("Calling sys_add again\n");
    check_add(path, passwd);

    //Call rm with correct parameters
    printf("Calling sys_rm\n");
    check_rm(path, passwd);

    //Call rm again expected to receive RES_NOT_PROTECTED_ERR
    printf("Calling sys_rm again\n");
    check_rm(path, passwd);

	return 0;
}