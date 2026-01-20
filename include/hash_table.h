//
// Created by Constantin on 06/01/2026.
//

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "hash_functions.h"
#include <stdint.h>

typedef struct hash_table_priv hash_table_priv;
typedef struct hash_table_t hash_table_t;

typedef int (*ht_insertFunction)(hash_table_t *, void *, void *);
typedef int (*ht_removeFunction)(hash_table_t *, void *);
typedef void *(*ht_searchFunction)(hash_table_t *, void *);

typedef int (*cmpFunction)(void *, void *);

struct hash_table_t {
    ht_insertFunction insert;
    ht_removeFunction remove;
    ht_searchFunction search;
    hash_table_priv *private;
};



hash_table_t *new_hash_table(size_t data_size, size_t key_length, size_t init_size, cmpFunction cmp);
void delete_hash_table(hash_table_t *ht);

int hash_table_insert(hash_table_t *ht, void *key, void *data);
void *hash_table_search(hash_table_t *ht, void *key);
int hash_table_delete(hash_table_t *ht, void *key);

int hash_table_resize(hash_table_t *ht, size_t new_size);

int hash_table_bucket_insert(hash_table_priv *table, unsigned char *bucket, void *key, void *data);
int is_zero(unsigned char *buf, size_t size);
#endif //HASH_TABLE_H
