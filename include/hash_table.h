//
// Created by Constantin on 02/01/2026.
//

#ifndef HASH_TABLE_H
#define HASH_TABLE_H
#include <stdint.h>

typedef int (*hashFunction)(const char *, unsigned int);

typedef struct dynamic_perfect_hash_table_priv dynamic_perfect_hash_table_priv, dpht_priv;
typedef struct first_level_ht_node first_level_ht_node;
typedef struct dpht {
    dynamic_perfect_hash_table_priv *priv;
}dpHashTable;

/*__________________________________________________HASH_FUNCTIONS____________________________________________________*/
unsigned int MurMurHash(const char *str, unsigned int length);
unsigned int FastHash(const char *str,unsigned int length);

uint64_t fasthash64(const void *buf, size_t len, uint64_t seed);
void MurmurHash3_x86_32 ( const void * key, int len,
                          uint32_t seed, void * out );


#endif //HASH_TABLE_H
