#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *filename;
    size_t truncated_size = 5;

    // Get target file from parameters
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return -1;
    }
    filename = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(filename, argv[1]);

    int res = truncate(filename, truncated_size);
    //Truncate
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
    printf("File '%s' truncated\n", filename);
    return 0;
}