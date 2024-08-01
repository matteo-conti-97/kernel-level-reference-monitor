#include <stdio.h>

int main() {
    // Define the file path
    const char *filePath = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt";

    // Open the file in read mode
    FILE *file = fopen(filePath, "w");

    // Check if the file was opened successfully
    if (file == NULL) {
        // Print an error message if the file could not be opened
        perror("Error opening file");
        return 1;
    }

    // File opened successfully, you can now read from the file
    // Example: reading a character from the file
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    // Close the file
    fclose(file);

    return 0;
}