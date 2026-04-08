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

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdint.h>

typedef struct hash_table_priv hash_table_priv;
typedef struct hash_table_t hash_table_t;

typedef int (*ht_insertFunction)(hash_table_t *, void *, void *);
typedef int (*ht_removeFunction)(hash_table_t *, void *);
typedef void *(*ht_searchFunction)(hash_table_t *, void *);


struct hash_table_t {
    ht_insertFunction insert;
    ht_removeFunction remove;
    ht_searchFunction search;
    hash_table_priv *private;
};



hash_table_t *new_hash_table(size_t data_size, size_t key_length, size_t init_size);
void delete_hash_table(hash_table_t *ht);

int hash_table_insert(hash_table_t *ht, void *key, void *data);
void *hash_table_search(hash_table_t *ht, void *key);
int hash_table_delete(hash_table_t *ht, void *key);

int hash_table_resize(hash_table_t *ht, size_t new_size);

int hash_table_bucket_insert(const hash_table_priv *table, unsigned char *bucket, const void *key, const void *data);
int is_zero(const unsigned char *buf, size_t size);
#endif //HASH_TABLE_H
