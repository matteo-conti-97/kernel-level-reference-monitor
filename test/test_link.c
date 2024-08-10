#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *target_file;
    char *target_link;

    // Get target file from parameters
    if (argc < 3) {
        printf("Usage: %s <file> <link>\n", argv[0]);
        return -1;
    }
    target_file = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(target_file, argv[1]);
    target_link = (char *)malloc(strlen(argv[2]) + 1);
    strcpy(target_link, argv[2]);

    // Create the hard link
    int res = link(target_file, target_link);
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

    printf("Hard link created successfully\n");

    return 0;
}
