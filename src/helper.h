/*
    Author: Harkirat Singh
    Description: Utilities and helper functions
*/
#pragma once

#ifndef _PROJECT_HELPER_H
#define _PROJECT_HELPER_H

#include <stdio.h>
#include <openssl/rand.h>

#define FAILED                      0x1
#define SUCCESS                     0x0

/*
    Params:
        key:   allocated memory where to store key
        size:  sizeof(key)
    
    Description: generates the random bytes
*/
void generate_bytes(unsigned char *key, size_t size);

void print_bytes(unsigned char *bytes, size_t size);

void read_hex(unsigned char *dat, unsigned char *dest, size_t size);

unsigned char *generate_random_bytes(int length);

#endif //_PROJECT_HELPER_H