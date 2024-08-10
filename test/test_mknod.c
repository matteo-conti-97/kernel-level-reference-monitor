#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *pathname;

    // Get target file from parameters
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return -1;
    }

    pathname = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(pathname, argv[1]);


    // Create a regular file using mknod
    int res = mknod(pathname, S_IFREG | 0666, 0);
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

    printf("File '%s' created successfully using mknod.\n", pathname);
    return 0;
}
