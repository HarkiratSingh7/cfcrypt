/*
    Author: Harkirat Singh
    Description: Utility for AES encryption/decrption
*/

#include <stddef.h>
#include <openssl/aes.h>

#define SALT_SIZE                   0x10
#define ITERATIONS                  10000

enum AES_ALGORITHMS {
    AES_128,
    AES_192,
    AES_256
};

/*
    Description: For encrypting plain_text with key and iv
*/
int aes_encrypt(const unsigned char *plain_text,
                 size_t plain_text_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int algorithm,
                 unsigned char *cipher_text);

/*
    Description: For decrypting plain_text with key and iv
*/
int aes_decrypt(const unsigned char *cipher_text,
                 size_t cipher_text_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int algorithm,
                 unsigned char *plain_text);
