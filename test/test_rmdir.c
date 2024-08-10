#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define TARGET_DIR "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"

int main(int argc, char *argv[]) {


    // Attempt to create the directory
    int res = rmdir(TARGET_DIR);

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
    printf("Directory '%s' removed successfully.\n", TARGET_DIR);
    return 0;
}
