//
// Created by Constantin on 03/01/2026.
//

#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H
#include <stdint.h>
typedef int (*hashFunction)(const char *, unsigned int);


unsigned int MurMurHash(const char *str, unsigned int length);
unsigned int FastHash(const char *str,unsigned int length);

unsigned int RSHash(const char* str, unsigned int length);
unsigned int JSHash(const char* str, unsigned int length);
unsigned int BKDRHash(const char* str, unsigned int length);
unsigned int SDBMHash(const char* str, unsigned int length);
unsigned int DJBHash(const char* str, unsigned int length);
unsigned int DEKHash(const char* str, unsigned int length);
unsigned int APHash(const char* str, unsigned int length);

/*GitHub code*/
//murmur hash

void MurmurHash3_x86_32  ( const void * key, int len, uint32_t seed, void * out );

void MurmurHash3_x86_128 ( const void * key, int len, uint32_t seed, void * out );

void MurmurHash3_x64_128 ( const void * key, int len, uint32_t seed, void * out );

//fasthash
uint64_t fasthash64(const void *buf, size_t len, uint64_t seed);

static hashFunction HF_ARRAY[9] = {MurMurHash, FastHash, RSHash, JSHash, BKDRHash, SDBMHash, DJBHash, DEKHash, APHash};


#endif //HASH_FUNCTIONS_H
