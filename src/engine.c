/*
    Author: Harkirat Singh
    Description: Core functionality of the project
*/

#include "engine.h"
#include "aes.h"
#include "file_handler.h"

/*
    Common function for AES encryption
*/
static int encrypt_aes_common(const char *input_file,
                              const char *output_file,
                              unsigned char *key,
                              unsigned char *iv,
                              int key_length)
{
    /* Read from file */
    int input_file_size;
    unsigned char *file_buff = read_file(input_file, &input_file_size);

    if (!file_buff) return FAILED;

    /* Allocate memory to load file and do operations */
    unsigned char *output_data = calloc(1, input_file_size 
                                           + AES_BLOCK_SIZE
                                           + AES_128_IV_LENGTH);
    
    /* Copy IV to the output data */
    for (int i = 0; i < AES_128_IV_LENGTH; i++)
        output_data[i] = iv[i];
    
    /* Select the algorithm */
    int algorithm;
    if (key_length == AES_128_KEY_LENGTH)
        algorithm = AES_128;
    else if (key_length == AES_192_KEY_LENGTH)
        algorithm = AES_192;
    else if (key_length == AES_256_KEY_LENGTH)
        algorithm = AES_256;
    else
    {
        printf("INVALID ALGORITHM");
        return FAILED;
    }

    /* Call the encryption function */
    int cipher_text_len = aes_encrypt(file_buff,
                                      input_file_size,
                                      key,
                                      iv, 
                                      algorithm,
                                      output_data + AES_128_IV_LENGTH);

    /* Write the data to file */
    write_file(output_file, output_data, AES_128_IV_LENGTH + cipher_text_len);

    /* Free the memory allocation */
    free(output_data);
    free(file_buff);
}

/*
    Common function for AES decryption
*/
static int decrypt_aes_common(const char *input_file,
                              const char *output_file,
                              const unsigned char *key,
                              int key_length)
{
    /* Read the encrypted file */
    int input_file_size;
    unsigned char *file_buff = read_file(input_file, &input_file_size);

    if (!file_buff) return FAILED;

    /* Allocate memory to load file and do operations */
    unsigned char *output_data = calloc(1, input_file_size 
                                           + AES_BLOCK_SIZE);
    
    /* Read IV from the first 128 bits of input file */
    unsigned char iv[AES_128_IV_LENGTH];
    for (int i = 0; i < sizeof(iv); i++)
        iv[i] = file_buff[i];
    
    /* Select the algorithm */
    int algorithm;
    if (key_length == AES_128_KEY_LENGTH)
        algorithm = AES_128;
    else if (key_length == AES_192_KEY_LENGTH)
        algorithm = AES_192;
    else if (key_length == AES_256_KEY_LENGTH)
        algorithm = AES_256;
    else
    {
        printf("INVALID ALGORITHM");
        return FAILED;
    }

    /* Call decryption function */
    int plain_text_length = aes_decrypt(file_buff + sizeof(iv),
                                        input_file_size - sizeof(iv),
                                        key,
                                        iv,
                                        algorithm,
                                        output_data);

    /* Write data to file */
    write_file(output_file, output_data, plain_text_length);

    /* Free memory allocations */
    free(output_data);
    free(file_buff);

    return SUCCESS;
}

/*
    Encrypt the file with random 128 bit AES encryption key
*/
int encrypt_aes_128_file_random(const char *input_file,
                                const char *output_file,
                                unsigned char *key)
{
    /* Generate 128 bit AES key */
    generate_bytes(key, AES_128_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_128_KEY_LENGTH))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 128 bit AES encryption key
*/
int decrypt_aes_128_file_with_key(const char *input_file,
                                  const char *output_file,
                                  const unsigned char *key)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_128_KEY_LENGTH);
}


/*
    Encrypt the file with random 192 bit AES encryption key
*/
int encrypt_aes_192_file_random(const char *input_file,
                                const char *output_file,
                                unsigned char *key)
{
    /* Generate 128 bit AES key */
    generate_bytes(key, AES_192_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_192_KEY_LENGTH))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 192 bit AES encryption key
*/
int decrypt_aes_192_file_with_key(const char *input_file,
                                  const char *output_file,
                                  const unsigned char *key)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_192_KEY_LENGTH);
}

/*
    Encrypt the file with random 256 bit AES encryption key
*/
int encrypt_aes_256_file_random(const char *input_file,
                                 const char *output_file,
                                 unsigned char *key)
{
    /* Generate 256 bit AES key */
    generate_bytes(key, AES_256_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_256_KEY_LENGTH))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 256 bit AES encryption key
*/
int decrypt_aes_256_file_with_key(const char *input_file,
                                  const char *output_file,
                                  const unsigned char *key)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_256_KEY_LENGTH);
}