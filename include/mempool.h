//
// Created by Constantin on 22/09/2025.
//

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stddef.h>

typedef struct mempool mempool_t;
typedef struct memory_extension memext_t;

typedef void* (*allocator)(mempool_t *);
typedef void (*deallocator)(mempool_t *, void *);
typedef int (*extend)(mempool_t *);

mempool_t *new_mempool(size_t cell_count, size_t cell_size);
void free_mempool(mempool_t * pool);

//for cell size of 8 bytes and larger
void *salloc(mempool_t *pool);
void sfree(mempool_t *pool, void *ptr);
    //helper
int memextend(mempool_t *pool);

//for cell size smaller than 8 bytes

//universal utilities
int is_empty(mempool_t *pool);
float get_capacity(mempool_t *pool);
size_t mempool_size(mempool_t *pool);

#endif //MEMPOOL_H
