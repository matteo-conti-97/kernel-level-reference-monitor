#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

int main() {
    const char *filename = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt";
    size_t truncated_size = 5;

    //Truncate
    if (truncate(filename, truncated_size) == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                break;
            default:
                printf("Error -> %s\n", strerror(errno));
                break;
        }
        return 1;
    }

    return 0;
}
