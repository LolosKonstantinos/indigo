
#ifndef INDIGO_DUCKTABLE_H
#define INDIGO_DUCKTABLE_H

#include "hash_functions.h"
#include <stdint.h>

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

typedef struct ducktable_t ducktable_t;

ducktable_t *new_ducktable(int key_size, int data_size, uint64_t init_size,hashFunction hash_function);
void free_ducktable(ducktable_t *ducktable);

int ducktable_search(ducktable_t *ducktable,const char *restrict key);
int ducktable_retrieve(ducktable_t *ducktable,const char *restrict key, void *restrict data);
int ducktable_access(ducktable_t *ducktable,const char *restrict key, void **data);
int ducktable_insert(ducktable_t *ducktable,const char *restrict key,const char *restrict data);
int ducktable_remove(ducktable_t *ducktable,const char *restrict key);

void ducktable_lock(ducktable_t *ducktable);
void ducktable_unlock(ducktable_t *ducktable);

// void ducktable_read_lock(ducktable_t *ducktable);
// void ducktable_write_lock(ducktable_t *ducktable);

int ducktable_rehash(ducktable_t *ducktable);
#endif // INDIGO_DUCKTABLE_H
