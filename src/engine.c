/*
    Author: Harkirat Singh
    Description: Core functionality of the project
*/

#include "engine.h"
#include "file_handler.h"

#include <string.h>

static int derive_key(const char *password, 
                      const unsigned char *salt, 
                      unsigned char *key, 
                      size_t key_size) {
    if (!PKCS5_PBKDF2_HMAC(password, 
                           strlen(password), 
                           salt, 
                           SALT_SIZE, 
                           ITERATIONS, 
                           EVP_sha256(), 
                           key_size, 
                           key)) {
        return 0;
    }
    return 1;
}

/*
    Common function for AES encryption

    is_password : means key is password and therefore generate additional salt
*/
static int encrypt_aes_common(const char *input_file,
                              const char *output_file,
                              unsigned char **key,
                              unsigned char *iv,
                              int key_length,
                              int is_password)
{
    /* Generate salt */
    unsigned char salt[SALT_SIZE];
    generate_bytes(salt, SALT_SIZE);
    if (is_password)
    {
        unsigned char *new_key = malloc(key_length);
        if (!derive_key(*key, salt, new_key, key_length))
        {
            perror("Error deriving key\n");
            return FAILED;
        }

        free(*key);
        *key = new_key;
    }

    /* Read from file */
    int input_file_size;
    unsigned char *file_buff = read_file(input_file, &input_file_size);

    if (!file_buff) return FAILED;

    int salt_size = is_password ? SALT_SIZE : 0;

    /* Allocate memory to load file and do operations */
    unsigned char *output_data = calloc(1, input_file_size 
                                           + AES_BLOCK_SIZE
                                           + AES_128_IV_LENGTH
                                           + salt_size);
    
    /* Copy IV to the output data */
    for (int i = 0; i < AES_128_IV_LENGTH; i++)
        output_data[i] = iv[i];
    
    if (is_password)
    {
        /* Copy password salt to the output data */
        for (int i = 0; i < SALT_SIZE; i++)
            *(output_data + AES_128_IV_LENGTH + i) = salt[i];
    }
    
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
                                      *key,
                                      iv, 
                                      algorithm,
                                      output_data + AES_128_IV_LENGTH 
                                      + salt_size);

    /* Write the data to file */
    write_file(output_file, output_data, AES_128_IV_LENGTH + cipher_text_len
                                         + salt_size);

    /* Free the memory allocation */
    free(output_data);
    free(file_buff);
}

/*
    Common function for AES decryption
*/
static int decrypt_aes_common(const char *input_file,
                              const char *output_file,
                              unsigned char **key,
                              int key_length,
                              int is_password)
{
    int salt_size = is_password ? SALT_SIZE : 0;
    /* Read the encrypted file */
    int input_file_size;
    unsigned char *file_buff = read_file(input_file, &input_file_size);

    if (!file_buff) return FAILED;

    /* Allocate memory to load file and do operations */
    unsigned char *output_data = calloc(1, input_file_size 
                                           + AES_BLOCK_SIZE);
    
    /* Read IV from the first 128 bits of input file */
    unsigned char iv[AES_128_IV_LENGTH];
    for (int i = 0; i < AES_128_IV_LENGTH; i++)
        iv[i] = file_buff[i];
    
    unsigned char salt[SALT_SIZE];
    if (is_password)
    {
        for (int i = 0; i < SALT_SIZE; i++)
            salt[i] = file_buff[i + AES_128_IV_LENGTH];
        
        unsigned char *new_key = malloc(key_length);
        if (!derive_key(*key, salt, new_key, key_length))
        {
            perror("Error deriving key\n");
            return FAILED;
        }

        free(*key);
        *key = new_key;
    }
    
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
    int plain_text_length = aes_decrypt(file_buff + AES_128_IV_LENGTH 
                                        + salt_size,
                                        input_file_size - AES_128_IV_LENGTH
                                        - salt_size,
                                        *key,
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
int encrypt_aes_128_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new, 
                         int is_password)
{
    if (!key && !*key)
    {
        perror("Invalid key provided.");
        return FAILED;
    }

    /* Generate 128 bit AES key if requried */
    if (generate_new && !is_password) generate_bytes(*key, AES_128_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_128_KEY_LENGTH,
                                     is_password))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 128 bit AES encryption key
*/
int decrypt_aes_128_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_128_KEY_LENGTH,
                               is_password);
}


/*
    Encrypt the file with random 192 bit AES encryption key
*/
int encrypt_aes_192_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new,
                         int is_password)
{
    if (!key)
    {
        perror("Invalid key provided.");
        return FAILED;
    }

    /* Generate 192 bit AES key if required */
    if (generate_new && !is_password) generate_bytes(*key, AES_192_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_192_KEY_LENGTH,
                                     is_password))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 192 bit AES encryption key
*/
int decrypt_aes_192_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_192_KEY_LENGTH,
                               is_password);
}

/*
    Encrypt the file with random 256 bit AES encryption key
*/
int encrypt_aes_256_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new,
                         int is_password)
{
    if (!key)
    {
        perror("Invalid key provided.");
        return FAILED;
    }

    /* Generate 256 bit AES key if required */
    if (generate_new && !is_password) generate_bytes(*key, AES_256_KEY_LENGTH);
    
    /* Generate 128 bit IV */
    unsigned char iv[AES_128_IV_LENGTH];
    generate_bytes(iv, sizeof(iv));

    if (FAILED == encrypt_aes_common(input_file,
                                     output_file,
                                     key,
                                     iv,
                                     AES_256_KEY_LENGTH,
                                     is_password))
        return FAILED;

    return SUCCESS;
}

/*
    Decrypt the file with 256 bit AES encryption key
*/
int decrypt_aes_256_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password)
{
    return decrypt_aes_common(input_file,
                               output_file,
                               key,
                               AES_256_KEY_LENGTH,
                               is_password);
}