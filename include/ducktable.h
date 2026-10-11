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
#ifndef INDIGO_DUCKTABLE_H
#define INDIGO_DUCKTABLE_H

#include "hash_functions.h"

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

typedef struct ducktable_t ducktable_t;
typedef struct ducktable_iterator_t ducktable_iterator_t;

ducktable_t *new_ducktable(int key_size, int key_offset, int data_size, uint64_t init_size);
void free_ducktable(ducktable_t *ducktable);

int ducktable_search(ducktable_t *ducktable,const char *restrict key);
int ducktable_retrieve(ducktable_t *ducktable,const char *restrict key, void *restrict data);
int ducktable_access(ducktable_t *ducktable,const char *restrict key, void **data);
int ducktable_insert(ducktable_t *ducktable, const char *restrict data);
int ducktable_remove(ducktable_t *ducktable,const char *restrict key);

void ducktable_lock(ducktable_t *ducktable);
void ducktable_unlock(ducktable_t *ducktable);

int ducktable_insert_ts(ducktable_t *ducktable, const char *restrict data);
int ducktable_remove_ts(ducktable_t *ducktable,const char *restrict key);
int ducktable_search_ts(ducktable_t *ducktable,const char *restrict key);
int ducktable_retrieve_ts(ducktable_t *ducktable,const char *restrict key, void *restrict data);

// void ducktable_read_lock(ducktable_t *ducktable);
// void ducktable_write_lock(ducktable_t *ducktable);

int ducktable_rehash(ducktable_t *ducktable);

int new_ducktable_iterator(ducktable_t *goosetable,ducktable_iterator_t **iterator);
void free_ducktable_iterator(ducktable_iterator_t **iterator);
int ducktable_has_next(ducktable_iterator_t *iterator);
void *ducktable_next(ducktable_iterator_t *iterator);
int ducktable_iterator_remove_current(ducktable_iterator_t *iterator);
#endif // INDIGO_DUCKTABLE_H
