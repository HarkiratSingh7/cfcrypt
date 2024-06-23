/*
    Author: Harkirat Singh
    Description: Utility for encrypting and decrypting files
*/
#ifndef _ENGINE_H
#define _ENGINE_H

#include "helper.h"
#include "aes.h"

#include <stddef.h>

#define ENCRYPTION_MODE             "encrypt"
#define DECRYPTION_MODE             "decrypt"

#define AES_128_ALGORITHM           "aes128"
#define AES_128_KEY_LENGTH          0x10
#define AES_192_ALGORITHM           "aes192"
#define AES_192_KEY_LENGTH          0x18
#define AES_256_ALGORITHM           "aes256"
#define AES_256_KEY_LENGTH          0x20

#define AES_128_IV_LENGTH           0x10

typedef int (*encryption_function)(const char *, 
                                   const char *, 
                                   unsigned char **,
                                   int,
                                   int);

typedef int (*decryption_function)(const char *,
                                   const char *,
                                   unsigned char **,
                                   int);
/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [IN/OUT] key:   memory allocation where to generate key
        generate_new:   0 to use key as it is otherwise 1 to generate
                        if is_password is specified then this is ignored
        is_password:    key parameter is actually a plain password input
        
    Description: Reads from input_file location, generates a 128 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_128_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new,
                         int is_password);

/*
    Params:
        input_file:     file to read for decrypting
        output_file:    file to write after decryption
        key:            memory allocation where to read key
    
    Description: Reads from input_file location, use a 128 bit AES 
                 encryption key and 128 bit IV present in the starting of 
                 encrypted file. Decrypts the input_file, and stores plain text 
                 into output_file location.
    
    Returns: 1 if error else 0
*/
int decrypt_aes_128_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password);


/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [IN/OUT] key:   memory allocation where to generate key
        generate_new:   0 to use key as it is otherwise 1 to generate
                        if is_password is specified then this is ignored
        is_password:    key parameter is actually a plain password input
        
    Description: Reads from input_file location, generates a 192 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_192_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new,
                         int is_password);

/*
    Params:
        input_file:     file to read for decrypting
        output_file:    file to write after decryption
        key:            memory allocation where to read key
    
    Description: Reads from input_file location, use a 192 bit AES 
                 encryption key and 128 bit IV present in the starting of 
                 encrypted file. Decrypts the input_file, and stores plain text 
                 into output_file location.
    
    Returns: 1 if error else 0
*/
int decrypt_aes_192_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password);



/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [IN/OUT] key:   memory allocation where to generate key
        generate_new:   0 to use key as it is otherwise 1 to generate
                        if is_password is specified then this is ignored
        is_password:    key parameter is actually a plain password input
        
    Description: Reads from input_file location, generates a 256 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_256_file(const char *input_file,
                         const char *output_file,
                         unsigned char **key,
                         int generate_new,
                         int is_password);

/*
    Params:
        input_file:     file to read for decrypting
        output_file:    file to write after decryption
        key:            memory allocation where to read key
    
    Description: Reads from input_file location, use a 256 bit AES 
                 encryption key and 128 bit IV present in the starting of 
                 encrypted file. Decrypts the input_file, and stores plain text 
                 into output_file location.
    
    Returns: 1 if error else 0
*/
int decrypt_aes_256_file_with_key(const char *input_file,
                                  const char *output_file,
                                  unsigned char **key,
                                  int is_password);


#endif