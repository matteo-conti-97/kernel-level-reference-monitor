#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    char *old_filename;
    char *new_filename;

    // Get target file from parameters
    if (argc < 3) {
        printf("Usage: %s <old_filename> <new_filename>\n", argv[0]);
        return -1;
    }
    old_filename = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(old_filename, argv[1]);
    new_filename = (char *)malloc(strlen(argv[2]) + 1);
    strcpy(new_filename, argv[2]);

    int res = rename(old_filename, new_filename);
    //Rename the file
    if (res == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                return -1;
            default:
                printf("Error -> %s\n", strerror(errno));
                return -1;
        }
    }
    printf("File '%s' renamed to '%s'.\n", old_filename, new_filename);
    return 0;
}