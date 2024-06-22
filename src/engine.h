/*
    Author: Harkirat Singh
    Description: Utility for encrypting and decrypting files
*/
#ifndef _ENGINE_H
#define _ENGINE_H

#include "helper.h"

#include <stddef.h>

#define ENCRYPTION_MODE             "encrypt"
#define DECRYPTION_MODE             "decrypt"

#define AES_ALGORITHM               "aes"
#define AES_256_KEY_LENGTH          0x20
#define AES_192_KEY_LENGTH          0x18
#define AES_128_KEY_LENGTH          0x10
#define AES_128_IV_LENGTH           0x10

/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [OUT] key:            memory allocation where to generate key
        
    Description: Reads from input_file location, generates a 128 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_128_file_random(const char *input_file,
                                const char *output_file,
                                unsigned char *key);

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
                                  const unsigned char *key);


/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [OUT] key:            memory allocation where to generate key
        
    Description: Reads from input_file location, generates a 192 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_192_file_random(const char *input_file,
                                const char *output_file,
                                unsigned char *key);

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
                                  const unsigned char *key);



/*
    Params:
        input_file:     file to read for encrypting
        output_file:    file to write after encryption
        [OUT] key:            memory allocation where to generate key
        
    Description: Reads from input_file location, generates a 256 bit AES 
                 encryption key and 128 bit IV. Encrypts the input_file, and 
                 stores IV + encrypted_file into output_file location.
    
    Returns: 1 if error else 0
*/
int encrypt_aes_256_file_random(const char *input_file,
                                const char *output_file,
                                unsigned char *key);

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
                                  const unsigned char *key);


#endif