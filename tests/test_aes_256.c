#include "../src/engine.h"
#include "../src/file_handler.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FILE_SIZE 200000000

int main()
{
    printf("Testing the 256 AES file encryption / decryption\n");

    /* Create a big file */
    const char *file_name = "TEST3.txt";
    const char *out_file = "TEST3.enc";
    const char *dec_file = "TEST3.dec";

    FILE *fp;
    if ((fp = fopen(file_name, "wb")) == NULL)
    {
        perror("Failed to create file");
        return 1;
    }

    unsigned char *buff = generate_random_bytes(FILE_SIZE);
    fwrite(buff, 1, FILE_SIZE, fp);
    fclose(fp);

    unsigned char key[AES_256_KEY_LENGTH];
    encrypt_aes_256_file_random(file_name, out_file, key);
    decrypt_aes_256_file_with_key(out_file, dec_file, key);

    /* read file and compare contents */
    int file_size;
    unsigned char *filebuff = read_file(dec_file, &file_size);

    printf("Assertion Check: file_size == FILE_SIZE\n");
    assert(file_size == FILE_SIZE);
    
    printf("Assertion Check: (strcmp(buff, filebuff)) == 0\n");
    assert((strcmp(buff, filebuff)) == 0);

    free(buff);
    free(filebuff);

    return 0;
}