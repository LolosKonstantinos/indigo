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
#ifndef INDIGO_GOOSETABLE_H
#define INDIGO_GOOSETABLE_H

#include "hash_functions.h"

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

typedef struct goosetable_t goosetable_t;

goosetable_t *new_goosetable(int key_size, int data_size, uint64_t init_size,hashFunction hash_function);
void free_goosetable(goosetable_t *goosetable);

int goosetable_search(goosetable_t *goosetable,const char *restrict key);
int goosetable_retrieve(goosetable_t *goosetable,const char *restrict key, void *restrict data);
int goosetable_access(goosetable_t *goosetable,const char *restrict key, void **data);
int goosetable_insert(goosetable_t *goosetable,const char *restrict key,const char *restrict data);
int goosetable_remove(goosetable_t *goosetable,const char *restrict key);

void goosetable_lock(goosetable_t *goosetable);
void goosetable_unlock(goosetable_t *goosetable);

// void goosetable_read_lock(ducktable_t *ducktable);
// void goosetable_write_lock(ducktable_t *ducktable);

int goosetable_rehash(goosetable_t *goosetable);
#endif // INDIGO_GOOSETABLE_H
