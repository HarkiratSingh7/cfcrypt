/*
    Author: Harkirat Singh
    Description: Source for File Handler utilities
*/

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

/*
    Function for reading file
*/
unsigned char *read_file(const char *file_path, int *file_size)
{
    struct stat f_stat;
    
    if (stat(file_path, &f_stat) != 0)
    {
        perror("File does not exists");
        return NULL;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file)
    {
        perror("Unable to open file.");
        return NULL;
    }

    /* Allocate a buffer of size from f_stat */
    unsigned char *file_data = calloc(1, sizeof(char) * f_stat.st_size);
    if (!file_data)
    {
        perror("Unable to allocate memory. File too big");
        return NULL;
    }

    fread(file_data, 1, f_stat.st_size, file);
    fclose(file);

    *file_size = f_stat.st_size;
    return file_data;
}

/*
    Function for writing to file
*/
size_t write_file(const char *file_path, unsigned char *buffer, long size)
{
    FILE *file = fopen(file_path, "wb");

    if (!file)
    {
        perror("Failed to open file for writing.");
        return 0;
    }

    size_t bytes = fwrite(buffer, 1, size, file);
    fclose(file);
    
    return bytes;
}