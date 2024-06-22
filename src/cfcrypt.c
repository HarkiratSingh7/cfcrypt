#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "engine.h"
#include "file_handler.h"

void print_usage() {
    printf("cfcrypt [PARAMS] -i input.txt -o output.txt\n");
    printf("PARAMETERS:\n");
    printf("-m MODE\t\tMode, can be either encrypt or decrypt\n");
    printf("-a ALGO\t\tAlgorithms, possible values: aes128, aes192, aes256\n");
    printf("-k KEY \t\tInput Key, requried for decrypting, "
        "for encryption it will generate if not provided for encryption\n");
    printf("-s     \t\tStore the key in secure database "
        "(location in /etc/cfcrypt.conf)\n");
}


int main(int argc, char *argv[])
{
    print_usage();
}