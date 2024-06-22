#include "aes.h"

#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>

typedef const EVP_CIPHER* (*EVP_CIPHER_FUNC)();
typedef const EVP_MD* (*EVP_MD_FUNC)();

EVP_CIPHER_FUNC FUNCTIONS[] = {
    EVP_aes_128_cbc,
    EVP_aes_192_cbc,
    EVP_aes_256_cbc
};

int aes_encrypt(const unsigned char *plain_text,
                 size_t plain_text_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int algorithm,
                 unsigned char *cipher_text)
{
    if (algorithm < 0 || algorithm > sizeof(FUNCTIONS)/sizeof(FUNCTIONS[0]))
    {
        perror("Invalid algorithm type");
        abort();
    }

    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_EncryptInit_ex(ctx, FUNCTIONS[algorithm](), NULL, key, iv)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_EncryptUpdate(
            ctx, cipher_text, &len, plain_text, plain_text_len)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *cipher_text,
                 size_t cipher_text_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 int algorithm,
                 unsigned char *plain_text)
{
    if (algorithm < 0 || algorithm > sizeof(FUNCTIONS)/sizeof(FUNCTIONS[0]))
    {
        perror("Invalid algorithm type");
        abort();
    }

    EVP_CIPHER_CTX* ctx;

    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptInit_ex(ctx, FUNCTIONS[algorithm](), NULL, key, iv)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptUpdate(
            ctx, plain_text, &len, cipher_text, cipher_text_len)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len)) 
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}