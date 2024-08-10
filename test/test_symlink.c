#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
#define TARGET_LINK "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/test_symlink.txt"

int main(int argc, char *argv[]) {

    // Create the symbolic link
    int res = symlink(TARGET_FILE, TARGET_LINK);
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

    printf("Symbolic link created successfully\n");

    return 0;
}