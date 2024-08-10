#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"

int main() {
    ssize_t bytes_written;
    char *test_data = "Test data\n";

    int fd = open(TARGET_FILE, O_WRONLY | O_CREAT, 0644);
    // Attempt to open the file in write mode
    if (fd == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                return -1;
            default:
                printf("Error -> %s\n", strerror(errno));
                return -1;
        }
    }

    printf("File '%s' creates successfully.\n", TARGET_FILE);

    return 0;
}