#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <../reference-monitor/states.h>


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
	return 0;
}