#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <../reference-monitor/error_codes.h>


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
    char passwd[128] = "1234";
    char path[128] = "/home/matteo/ref_mon_test/test_file";

    if(argc < 2){
        printf("Usage: %s <num times>\n", argv[0]);
        return -1;
    }

    int num_times = atoi(argv[1]);

    for(int i = 0; i < num_times; i++)
        check_rm(path, passwd);

	return 0;
}