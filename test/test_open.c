#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"

int main() {
    int fd;
    ssize_t bytes_written;
    char *test_data = "Test data\n";

    // Attempt to open the file in write mode
    fd = open(TARGET_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        if (errno == EACCES) {
            printf("Write operation was blocked as expected.\n");
        } else {
            printf("Failed to open file: %s\n", strerror(errno));
        }
        return 1;
    }

    // Attempt to write to the file
    bytes_written = write(fd, test_data, strlen(test_data));
    if (bytes_written == -1) {
        if (errno == EACCES) {
            printf("Write operation was blocked as expected.\n");
        } else {
            printf("Failed to write to file: %s\n", strerror(errno));
        }
        close(fd);
        return 1;
    }

    printf("Write operation succeeded, probe is not working.\n");

    close(fd);
    return 0;
}