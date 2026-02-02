//
// Created by Constantin on 02/01/2026.
//

#ifndef DPHT_H
#define DPHT_H
#include <stdint.h>
#include "hash_functions.h"

typedef struct dynamic_perfect_hash_table_priv dynamic_perfect_hash_table_priv, dpht_priv;
typedef struct first_level_ht_node first_level_ht_node;
typedef struct dpht {
    dynamic_perfect_hash_table_priv *priv;
}dpHashTable;

dpHashTable *new_dynamic_perfect_hash_table(size_t data_size, size_t key_count,uint32_t max_key_length);
void free_dynamic_perfect_hash_table(dpHashTable *table);

int dpht_insert(dpHashTable *table, const char *key, size_t key_size, const char *value);
int dpht_remove(dpHashTable *table, const char *key);
int dpht_contains(dpHashTable *table, const char *key);
void *dpht_search(dpHashTable *table, const char *key);

int new_second_level_hash_table(first_level_ht_node *node, size_t cell_size, uint32_t key_length);
int resize_first_level_hash_table(dpHashTable *table);




#endif //DPHT_H
