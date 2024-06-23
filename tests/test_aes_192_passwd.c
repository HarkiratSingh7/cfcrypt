#include "../src/engine.h"
#include "../src/file_handler.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FILE_SIZE   200000000
#define PASSWD_LEN  0x1000

int main()
{
    printf("Testing the 192 AES file encryption / decryption with a plain password\n");

    /* Create a big file */
    const char *file_name = "TEST2_passwd.txt";
    const char *out_file = "TEST2_passwd.enc";
    const char *dec_file = "TEST2_passwd.dec";

    FILE *fp;
    if ((fp = fopen(file_name, "wb")) == NULL)
    {
        perror("Failed to create file");
        return 1;
    }

    unsigned char *passwd = generate_random_string(PASSWD_LEN);
    unsigned char *buff = generate_random_bytes(FILE_SIZE);
    fwrite(buff, 1, FILE_SIZE, fp);
    fclose(fp);

    unsigned char *key1 = calloc(1, PASSWD_LEN + 1);
    unsigned char *key2 = calloc(1, PASSWD_LEN + 1);
    memcpy(key1, passwd, PASSWD_LEN + 1);
    memcpy(key2, passwd, PASSWD_LEN + 1);
    printf("[DEBUG] password is\n");
    print_bytes(key1, PASSWD_LEN + 1);
    assert(SUCCESS == encrypt_aes_192_file(file_name, out_file, &key1, 0, 1));
    assert(SUCCESS == decrypt_aes_192_file_with_key(out_file, dec_file, &key2, 1));

    /* read file and compare contents */
    int file_size;
    unsigned char *filebuff = read_file(dec_file, &file_size);

    printf("Assertion Check: file_size == FILE_SIZE\n");
    assert(file_size == FILE_SIZE);
    
    printf("Assertion Check: (memcmp(buff, filebuff, file_size)) == 0\n");
    assert((memcmp(buff, filebuff, file_size)) == 0);

    free(buff);
    free(filebuff);
    free(key1);
    free(key2);
    free(passwd);

    return 0;
}