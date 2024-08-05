#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova2.txt"

int main() {
    ssize_t bytes_written;
    char *test_data = "Test data\n";
    int fd;

    fd = open(TARGET_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    // Attempt to open the file in write mode
    if (fd == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                break;
            default:
                printf("Error -> %s\n", strerror(errno));
                break;
        }
        return 1;
    }
    
    // Write the test data to the file
    bytes_written = write(fd, test_data, strlen(test_data));
    if (bytes_written == -1) {
        printf("Error -> %s\n", strerror(errno));
        return 1;
    }
    return 0;
}