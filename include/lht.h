/*
Copyright (c) 2026 Lolos Konstantinos

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

#ifndef INDIGO_LHT_H
#define INDIGO_LHT_H

#include <stdint.h>

typedef struct lht_priv lht_priv;
typedef struct linked_hash_table_t linked_hash_table_t, lht_t;

typedef int (*lht_insertFunction)(linked_hash_table_t *, void *, void *);
typedef int (*lht_removeFunction)(linked_hash_table_t *, void *);
typedef void *(*lht_searchFunction)(linked_hash_table_t *, void *);

typedef struct lht_node_t {
    struct lht_node_t *next;
    struct lht_node_t *prev;
    void *data;
}lht_node_t;

struct linked_hash_table_t {
    lht_insertFunction insert;
    lht_removeFunction remove;
    lht_searchFunction search;
    lht_priv *private;
};

lht_t *new_lht(size_t data_size, size_t key_length, size_t init_size);
void delete_lht(linked_hash_table_t *ht);

int lht_insert(linked_hash_table_t *ht, void *key, void *data);
void *lht_search(linked_hash_table_t *ht, void *key);
int lht_delete(linked_hash_table_t *ht, void *key);

int lht_bucket_insert(const lht_priv *table, unsigned char *bucket, const void *key, const void *data);

int lht_lock(lht_t *ht);
int lht_unlock(lht_t *ht);

int lht_list(lht_t *ht, lht_node_t **list);
#endif //INDIGO_LHT_H