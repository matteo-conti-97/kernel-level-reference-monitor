#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    char *target_link;
    
    //Get target file from parameters
    if (argc < 2) {
        printf("Usage: %s <link>\n", argv[0]);
        return -1;
    }
    target_link = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(target_link, argv[1]);

    // Attempt to unlink the file
    int res = unlink(target_link);
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
    printf("File unlinked\n");

    return 0;
}
