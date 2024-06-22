/*
    Author: Harkirat Singh
    Description: File Handler module for reading and saving to the file
*/

/*
    Params: 
        file_path:  pointer to file path string

    Description: Tries to read from the file path specified

    Returns: NULL if operation was unsuccessful, else pointer to buffer

    Note: It is the duty of user to free the memory referenced by the pointer
          returned by this function.
*/
unsigned char *read_file(const char *file_path, int *file_size);

/*
    Params:
        file_path:  pointer to file path string
        buffer:     buffer to write to the file
        size:       size of buffer

    Description: Tries to write to the file path specified
    
    Returns:    0 if operation was unsuccessful, 
                else returns number of bytes writter
*/
size_t write_file(const char *file_path, unsigned char *buffer, long size);