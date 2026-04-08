/*Copyright (c) 2026 Lolos Konstantinos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
