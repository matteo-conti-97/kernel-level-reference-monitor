#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main() {
    const char *old_filename = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt";
    const char *new_filename = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_rename.txt";

    int res = rename(old_filename, new_filename);
    //Rename the file
    if (res == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                break;
            default:
                printf("Error -> %s\n", strerror(errno));
                break;
        }
    }
    return 0;
}