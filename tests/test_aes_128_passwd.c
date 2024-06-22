#include "../src/engine.h"
#include "../src/file_handler.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FILE_SIZE   200000000
#define PASSWD_LEN  0x40

int main()
{
    printf("Testing the 128 AES file encryption / decryption\n");

    /* Create a big file */
    const char *file_name = "TEST1.txt";
    const char *out_file = "TEST1.enc";
    const char *dec_file = "TEST1.dec";

    FILE *fp;
    if ((fp = fopen(file_name, "wb")) == NULL)
    {
        perror("Failed to create file");
        return 1;
    }

    unsigned char *passwd = "ASecretPassword";
    unsigned char *buff = generate_random_bytes(FILE_SIZE);
    fwrite(buff, 1, FILE_SIZE, fp);
    fclose(fp);

    unsigned char *key1 = calloc(1, 128);
    unsigned char *key2 = calloc(1, 128);
    strcpy(key1, passwd);
    strcpy(key2, passwd);
    assert(SUCCESS == encrypt_aes_128_file(file_name, out_file, &key1, 0, 1));
    assert(SUCCESS == decrypt_aes_128_file_with_key(out_file, dec_file, &key2, 1));

    /* read file and compare contents */
    int file_size;
    unsigned char *filebuff = read_file(dec_file, &file_size);

    printf("Assertion Check: file_size == FILE_SIZE\n");
    assert(file_size == FILE_SIZE);
    
    printf("Assertion Check: (strcmp(buff, filebuff)) == 0\n");
    assert((strcmp(buff, filebuff)) == 0);

    free(buff);
    free(filebuff);
    free(key1);
    free(key2);
    return 0;
}