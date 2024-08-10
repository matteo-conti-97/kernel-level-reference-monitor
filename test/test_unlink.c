#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_LINK "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_unlink.txt"

int main(int argc, char *argv[]) {

    // Attempt to unlink the file
    int res = unlink(TARGET_LINK);
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
