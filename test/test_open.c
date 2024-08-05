#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define TARGET_FILE "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"

int main() {
    ssize_t bytes_written;
    char *test_data = "Test data\n";

    // Attempt to open the file in write mode
    if (open(TARGET_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644) == -1) {
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
    
    return 0;
}