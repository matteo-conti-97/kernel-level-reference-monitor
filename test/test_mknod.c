#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    const char *pathname = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/test_mknod";

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
