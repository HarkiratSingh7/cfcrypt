#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "engine.h"
#include "file_handler.h"

void print_usage() {
    printf("cfcrypt [PARAMS] -i input.txt -o output.txt\n");
    printf("PARAMETERS:\n");
    printf("-m MODE\t\tMode, can be either encrypt or decrypt\n");
    printf("-a ALGO\t\tAlgorithms, possible values: aes128, aes192, aes256\n");
    printf("-k \t\tInput Key, requried for decrypting, "
        "for encryption it will generate if not provided for encryption\n");
    printf("-p \t\tEncrypt using a password\n");
    printf("Note: -p and -k can't be used together\n");
}

enum {
    ENCYRPTION,
    DECRYPTION
};

int encrypt_with_method(const char *input_file,
                        const char *output_file,
                        unsigned char **input_key,
                        int password,
                        encryption_function encrypt_func_cb,
                        int key_length)
{
    int res = -1;

    unsigned char *key = malloc(key_length);

    if (input_key && *input_key) 
    {
        if (!password)
        {
            read_hex(*input_key, key, key_length);
            free(*input_key);
            *input_key = key;
        }
        res = encrypt_func_cb(input_file,
                              output_file,
                              input_key,
                              0,
                              password);
    }
    else
    {
        free(*input_key);
        *input_key = key;
        res = encrypt_func_cb(input_file,
                              output_file,
                              input_key,
                              1,
                              password);
    }

    if (res == FAILED)
    {
        printf("Unable to encrypt %s file with AES-%d algorithm.\n",
                            input_file, key_length * 8);
        return res;
    }

    printf("File encrypted successfully to: %s\n", output_file);
    
    if (strcmp(input_file, output_file))
        printf("Note: %s is not deleted.\n", input_file);
    
    if (!input_key) printf("Key Generated ");

    if (!password)
    {
        print_bytes(key, key_length);
    }
    
    return res;
}

int decrypt_with_method(const char *input_file,
                        const char *output_file,
                        unsigned char **input_key,
                        int password,
                        decryption_function decrypt_func_cb,
                        int key_length)
{
    unsigned char *key = malloc(key_length);
    if (!password)
    {
        read_hex(*input_key, key, key_length);
        free(*input_key);
        *input_key = key;
    }

    if (FAILED == decrypt_func_cb(input_file,
                                  output_file,
                                  input_key,
                                  password))
    {
        printf("Unable to decrypt %s file with AES-%d algorithm.\n",
                            input_file, key_length * 8);
        return FAILED;
    }

    printf("File decrypted successfully to: %s\n", output_file);
    
    if (strcmp(input_file, output_file))
        printf("Note: %s is not deleted.\n", input_file);
    
    return SUCCESS;
}

int main(int argc, char *argv[])
{
    int mode = -1, algorithm = -1;
    unsigned char *input_key = NULL;
    char *input_file = NULL;
    char *output_file = NULL;
    int password = 0;
    int non_password = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-m") == 0)
        {
            if (strcmp(argv[i + 1], ENCRYPTION_MODE) == 0)
                mode = ENCYRPTION;
            else if (strcmp(argv[i + 1], DECRYPTION_MODE) == 0)
                mode = DECRYPTION;
            else
            {
                printf("Invalid '%s' mode specified.\n", argv[i + 1]);
                print_usage();
                exit(EXIT_FAILURE);
            }
            i++;
        }
        else if (strcmp(argv[i], "-a") == 0)
        {
            if (strcmp(argv[i + 1], AES_128_ALGORITHM) == 0)
                algorithm = AES_128;
            else if (strcmp(argv[i + 1], AES_192_ALGORITHM) == 0)
                algorithm = AES_192;
            else if (strcmp(argv[i + 1], AES_256_ALGORITHM) == 0)
                algorithm = AES_256;
            else
            {
                printf("Invalid '%s' algorithm specified.\n", argv[i + 1]);
                print_usage();
                exit(EXIT_FAILURE);
            }
            i++;
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            if (i + 1 >= argc)
            {
                goto invalid_key;
            }
            int sz = strlen(argv[i + 1]);
            input_key = malloc(sz);
            memcpy(input_key, argv[i + 1], sz);
            if (!input_key || sz == 0 || input_key[0] == '-')
            {
invalid_key:
                printf("Invalid key specified.\n");
                print_usage();
                exit(EXIT_FAILURE);
            }
            i++;
            non_password = 1;
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            password = 1;
            char *password_input = getpass("Enter Password: ");
            int sz = strlen(password_input);
            input_key = malloc(sz);
            memcpy(input_key, password_input, sz);
            if (!input_key || sz == 0)
            {
                printf("Invalid password specified.\n");
                print_usage();
                exit(EXIT_FAILURE);
            }
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            input_file = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            output_file = argv[i + 1];
            i++;
        }
        else
        {
            printf("Invalid '%s' option specified.\n", argv[i]);
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (password && non_password)
    {
        printf("Option -k and -p can't be used together\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
    
    /* Check if options are specified */
    if (mode == -1)
    {
        print_usage();
        printf("Option -m <mode> is required\n");
        exit(EXIT_FAILURE);
    }
    else if (algorithm == -1)
    {
        print_usage();
        printf("Option -a <algorithm> is required\n");
        exit(EXIT_FAILURE);
    }
    else if (!input_file)
    {
        print_usage();
        printf("Input file -i <file> is required.");
        exit(EXIT_FAILURE);
    }
    else if (!output_file)
    {
        print_usage();
        printf("Output file -o <file> is required.");
        exit(EXIT_FAILURE);
    }

    if (password == 0)
    {
        if (!input_key && mode == DECRYPTION)
        {
            print_usage();
            printf("Input key is required.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (mode == ENCYRPTION)
    {
        if (algorithm == AES_128)
        {
            return encrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       encrypt_aes_128_file,
                                       AES_128_KEY_LENGTH);
        }
        else if (algorithm == AES_192)
        {
            return encrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       encrypt_aes_192_file,
                                       AES_192_KEY_LENGTH);
        }
        else if (algorithm == AES_256)
        {
            return encrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       encrypt_aes_256_file,
                                       AES_256_KEY_LENGTH);
        }
    }
    else if (mode == DECRYPTION)
    {
        if (algorithm == AES_128)
        {
            return decrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       decrypt_aes_128_file_with_key,
                                       AES_128_KEY_LENGTH);
        }
        else if (algorithm == AES_192)
        {
            return decrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       decrypt_aes_192_file_with_key,
                                       AES_192_KEY_LENGTH);
        }
        else if (algorithm == AES_256)
        {
            return decrypt_with_method(input_file,
                                       output_file,
                                       &input_key,
                                       password,
                                       decrypt_aes_256_file_with_key,
                                       AES_256_KEY_LENGTH);
        }
    }

    return FAILED;
}