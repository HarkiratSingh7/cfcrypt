#include "helper.h"

#include <openssl/err.h>

void generate_bytes(unsigned char *key, size_t size)
{
    if (!RAND_bytes(key, size))
    {
        printf("Key Size: %ld\n", size);
        perror("Unable to generate key");
        ERR_print_errors_fp(stderr);
        abort();
    }
}

void print_bytes(unsigned char *bytes, size_t size)
{
    for (int i = 0; i < size; i++)
        printf("%02x", bytes[i]);
    printf("\n");
}

static char get_hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void read_hex(unsigned char *dat, unsigned char *dest, size_t size)
{
    for (int i = 0; i < size; i++)
    {
        char first = dat[2 * i];
        char second = dat[2 * i + 1];
        dest[i] = get_hex_val(second) | (get_hex_val(first) << 4);
    }
}

unsigned char *generate_random_bytes(int length)
{
    char *str = malloc(length + 1);
    str[length] = 0;

    for (int i = 0; i < length; i++)
        str[i] = rand() % 256;
    
    return str;
}

char *generate_random_string(int length)
{
    static const char OFFSET = 32;
    static const char COUNT = (126 - 32 + 1);
    char *str = NULL;
    if (length)
    {
        str = (char*)malloc(sizeof(char) * (length + 1));

        if (!str)
            return NULL;
        
        for (int i = 0; i < length; i++)
        {
            char key = OFFSET + (rand() % COUNT);
            str[i] = key;
        }

        str[length] = '\0';
    }

    return str;
}