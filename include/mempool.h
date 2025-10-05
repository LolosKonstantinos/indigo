//
// Created by Constantin on 22/09/2025.
//

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stdlib.h>


#define MEMPOOL_MAX_SIZE (1<<30) //limit pool size to 1 GiB
#define MEMPOOL_MAX_EXTENSION_SIZE (1<<30) //limit each extension to 1 GiB

typedef void * EXT_HANDLE;

typedef struct mempool mempool_t;
typedef struct mempool_private mempool_private_t;
typedef struct memory_extension_tree_node ext_tree;
typedef struct memory_extension_ll_node ext_ll;

typedef void *(*alloc)(mempool_t *);
typedef void (*dealloc)(mempool_t *, void *);
typedef EXT_HANDLE (*memextend)(mempool_t *, size_t);
typedef void (*free_ext)(mempool_t, EXT_HANDLE);


struct mempool {
    alloc alloc;
    dealloc free;
    memextend extend;
    free_ext free_extension;

    int (*is_full)(const mempool_t *);
    float (*get_capacity)(const mempool_t *);
    size_t (*get_mempool_size)(const mempool_t *);

    struct mempool_private *private;
};

typedef struct mempool_attr {
    float growth_factor;
    char dynamic_pool;
}mempool_attr;

//init and destroy functionalities


mempool_t *new_mempool(size_t cell_count, size_t cell_size, const mempool_attr* attr);
void free_mempool(mempool_t * pool);

//allocators and deallocators

//default dynamic pool
void *dalloc(mempool_t *pool);
void dfree(mempool_t *pool, void *cell);

//extension utilities
int memextend_list(mempool_t *pool);
EXT_HANDLE memextend_list_manual(mempool_t* pool, size_t cell_count);
//they basically are the same but in case they are not in the future code will still work
void free_extension_list_manual(mempool_t *pool, EXT_HANDLE handle);
void remove_extension_list(mempool_t *pool, ext_ll *ext);

//static pool (both are true constant time)
void *salloc(mempool_t *pool);
void sfree(mempool_t *pool, void *cell);

//universal utilities
int is_full(const mempool_t *pool);
float get_capacity(const mempool_t *pool);
size_t get_mempool_size(const mempool_t *pool);
size_t get_cell_size(const mempool_t *pool);
size_t get_cell_count(const mempool_t *pool);

//todo
void optimise_mempool(mempool_t *pool);

#endif //MEMPOOL_H
