#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>


int main(int argc, char *argv[]) {
    ssize_t bytes_written;
    char *test_data = "Test data\n";
    char *target_file;

    //Get file path from parameters
    if(argc < 2){
        printf("Usage: %s <file_path>\n", argv[0]);
        return -1;
    }
    target_file = (char *) malloc(strlen(argv[1]) + 1);
    strcpy(target_file, argv[1]);

    printf("Opening file %s\n", target_file);

    int fd = open(target_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

    printf("File %s opened successfully.\n", target_file);
    
    // Write the test data to the file
    bytes_written = write(fd, test_data, strlen(test_data));
    if (bytes_written == -1) {
        switch(errno){
            case EACCES:
                printf("%s\n", strerror(errno));
                return -1;
            default:
                printf("Error -> %s\n", strerror(errno));
                return -1;
        }
    }

    close(fd);

    printf("Data written to file '%s'.\n", target_file);
    
    return 0;
}