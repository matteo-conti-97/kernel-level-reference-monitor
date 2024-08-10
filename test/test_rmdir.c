#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *target_dir;

    // Get target file from parameters
    if (argc < 2) {
        printf("Usage: %s <dir>\n", argv[0]);
        return -1;
    }
    target_dir = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(target_dir, argv[1]);

    // Attempt to create the directory
    int res = rmdir(target_dir);

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
    printf("Directory '%s' removed successfully.\n", target_dir);
    return 0;
}
