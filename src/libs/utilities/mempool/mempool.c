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
// TODO: needs redesign of the dynamic pool
//       remove base pool we only need extensions
//       each extension has fixed size 1<<alignment
//       memextend may create more than one extension according to the growth factor
//       extensions have their own free list, pool has a free list of available extensions

#include "mempool.h"

#include "../../../../third_party/log.c/log.h"

#include <pthread.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define FORCE_INLINE inline __attribute__((always_inline))

#ifdef _WIN32
#include <malloc.h>
#define aligned_alloc(alignment,size) (_aligned_malloc((size),(alignment)))
#define alingned_free(ptr) _aligned_free(ptr)

#else

#define aligned_free(ptr) free(ptr)

#endif


#define MEMPOOL_FLAG_LL 0x01
#define MEMPOOL_FLAG_EMPTY_EXTENSION 0x02

typedef struct memory_block_ll_node {
    void *data;

    void *first_free_cell;
    size_t cell_count;
    size_t capacity;   // the number of free cells in the extension

    struct memory_block_ll_node *next;
    struct memory_block_ll_node *next_free;
}memblock_t;

struct mempool_t {
    memblock_t *first_free_block; // pointer to the first free extension
    memblock_t *last_free_block;  // pointer to the last free extension
    memblock_t *all_blocks;    // a linked list of all the blocks in the pool

    size_t initial_cell_count;   // the number of cells requested initially
    size_t cell_size;    // the size in bytes of each cell
    size_t total_cell_count;     // the total number blocks
    float growth_rate; // the growth rate for the next extension's size.
                       //0 static, > 0 increasing size

    uint16_t alignment; // the power of 2 of the alignment
                       //allows constant time free, for any number of blocks
    int16_t cell_alignment;
    pthread_mutex_t mutex;
};

memblock_t *new_block(mempool_t * const pool)
{
    const uint8_t alignment = pool->alignment;
    const int16_t cell_alignment = pool->cell_alignment;
    const size_t cell_size = pool->cell_size;
    size_t cell_count = 0;
    memblock_t *block;
    void *data;
    uintptr_t first_free_cell;
    void *curr_cell;
    void *next_cell;

    //allocate the block
    block = malloc(sizeof(memblock_t));
    if (block == NULL) {
        log_error("[new_block] malloc failed allocating %d bytes for new block struct", sizeof(memblock_t));
        return NULL;
    }
    data = aligned_alloc(1<<alignment, 1<<alignment);
    if (block->data == NULL) {
        free(block);
        log_error("[new_block] aligned_alloc failed allocating %lld bytes with alignment %lld", 1<<alignment, 1<<alignment);
        return NULL;
    }
    //write the address of the block at the start of the array
    *(void **)data = block;
    //find the first address that is aligned to the cells
    first_free_cell = ((uintptr_t)data + sizeof(void *) + cell_alignment - 1) & (-cell_alignment);
    //calculate the cell count for this block
    cell_count = ((1<<alignment) - first_free_cell + (uintptr_t)data) / cell_size;

    //initialize the free list
    for (size_t i = 0; i < cell_count - 1; i++) {
        curr_cell = (void *)(first_free_cell + (i * cell_size));
        next_cell = curr_cell + cell_size;

        *(void **)curr_cell = next_cell;
    }
    curr_cell = (void *)(first_free_cell + ((cell_count - 1) * cell_size));
    *(void **)curr_cell = NULL;

    block->data = data;
    block->first_free_cell = (void *)first_free_cell;
    block->cell_count = cell_count;
    block->capacity = cell_count;

    //attach it to the block list
    block->next_free = pool->first_free_block;
    pool->first_free_block = block;
    block->next = pool->all_blocks;
    pool->all_blocks = block;

    pool->total_cell_count += cell_count;

    if (pool->last_free_block == NULL) {
        pool->last_free_block = block;
    }
    return block;
}

FORCE_INLINE void free_block(memblock_t * const block)
{
    aligned_free(block->data);
    free(block);
}

mempool_t *new_mempool_manual(const size_t cell_count, size_t cell_size, const int16_t cell_alignment,const  float growth_rate)
{
    mempool_t *pool;
    memblock_t *block;

    if (cell_count == 0 || cell_size == 0)
        return NULL;

    if (cell_size < sizeof(void *)) {
        cell_size = sizeof(void *);
    }

    // allocate the pool struct and the pool's memory

    pool = malloc(sizeof(mempool_t));
    if (pool == NULL) {
        log_error("[new_mempool_manual] malloc failed allocating %d bytes for memory pool structure", sizeof(mempool_t));
        return NULL;
    }

    //pad the cell size so that each cell is aligned to the data it holds
    cell_size = (cell_size + cell_alignment - 1) & (-cell_alignment);
    pool->alignment = (uint8_t)ceil(log2((double)(cell_count * cell_size  + sizeof(void *))));
#ifdef _WIN32
    //apparently windows has a maximum allocation size
    if (1<<pool->alignment > _HEAP_MAXREQ) pool->alignment = (uint8_t)floor(log2(_HEAP_MAXREQ));
#endif
    pool->cell_alignment = cell_alignment;
    pool->growth_rate = growth_rate;

    pool->cell_size = cell_size;
    pool->initial_cell_count = cell_count;

    pool->total_cell_count = 0;
    pool->all_blocks = NULL;
    pool->first_free_block = NULL;
    pool->last_free_block = NULL;

    //unfortunately the alignment of the cell is not guaranteed to be a power of
    //so it is virtually impossible to calculate a predetermined cell count

    //create the first block for the pool
    block = new_block(pool);
    if (block == NULL) {
        free(pool);
        return NULL;
    }

    // initialize the mutex
    pthread_mutex_init(&pool->mutex, NULL);

    return pool;
}

void free_mempool(mempool_t * const pool)
{
    memblock_t *curr;
    memblock_t *prev;

    if (pool == NULL)
        return;
    pthread_mutex_lock(&pool->mutex);

    // free the memory blocks
    curr = pool->all_blocks;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;

        free_block(prev);
    }

    // free the pool structure
    free(pool);
    pthread_mutex_unlock(&pool->mutex);

    pthread_mutex_destroy(&pool->mutex);
}

void *mempool_dalloc(mempool_t * const pool)
{
    void *cell = NULL;
    memblock_t *block;

    if (pool == NULL)
        return NULL;
    pthread_mutex_lock(&pool->mutex);

    // if there is no available space then we extend the pool
    if (pool->first_free_block == NULL) {
        if (memextend_pool(pool) != 0) {
            pthread_mutex_unlock(&pool->mutex);
            return NULL;
        }
    }

    block = pool->first_free_block;
    cell = block->first_free_cell;

    block->first_free_cell = *(void **)cell;

    --(block->capacity);

    if (block->capacity == 0) {
        pool->first_free_block = block->next_free;
    }

    pthread_mutex_unlock(&pool->mutex);
    return cell;
}

void mempool_free(mempool_t *pool, void *cell)
{
    memblock_t *block;
    uintptr_t data_addr;
    if (pool == NULL || cell == NULL)
        return;

    pthread_mutex_lock(&pool->mutex);

    data_addr = (uintptr_t)cell & -(1 << pool->alignment);
    block = *(void **)data_addr;

    *(void **)cell = block->first_free_cell;
    block->first_free_cell = cell;
    ++(block->capacity);

    if (block->capacity == 1) {
        if (pool->first_free_block == NULL) {
            pool->first_free_block = block;
        }
        pool->last_free_block->next_free = block;
        block->next_free = NULL;
    }
    pthread_mutex_unlock(&pool->mutex);
}

void *mempool_salloc(mempool_t * const pool)
{
    void *cell;
    memblock_t *block;

    if (pool == NULL)
        return NULL;

    pthread_mutex_lock(&pool->mutex);

    if (pool->first_free_block == NULL) {
        pthread_mutex_unlock(&pool->mutex);
        return NULL;
    }

    block = pool->first_free_block;
    cell = block->first_free_cell;

    // copy the address of the next cell to the free cell pointer
    block->first_free_cell = *((void **)cell);

    block->capacity--;

    if (block->capacity == 0) {
        pool->first_free_block = block->next_free;
    }

    pthread_mutex_unlock(&pool->mutex);

    return cell;
}

int memextend_pool(mempool_t * const pool)
{
    size_t total_cells;
    size_t cell_count;
    size_t block_count;

    if (pool == NULL)
        return -1;

    cell_count = pool->total_cell_count;

    // calculate the new size
    total_cells = (size_t) ((double)cell_count *  pool->growth_rate);

    block_count = (total_cells * pool->cell_size) / ((1<<pool->alignment) - (pool->cell_size)) ;

    if (block_count == 0)
        block_count = 1;

    for (size_t i = 0; i < block_count; i++) {
        if (new_block(pool) == NULL) {
            return 1;
        }
    }
    return 0;
}

void optimize_mempool(mempool_t *const pool)
{
    memblock_t *curr = NULL;
    memblock_t *prev = NULL;

    char one_free_block = 0;
    if (pool == NULL) return;

    pthread_mutex_lock(&pool->mutex);
    for (memblock_t *block = pool->all_blocks; block != NULL; block = block->next) {
        if (block->cell_count == block->capacity) {
            if (one_free_block == 1) {
                /*despite what clangd says there is no possible way that prev is NULL.
                  It can not be NULL, because that would require it being the first node
                  in the list. However, if the first node is free we skip it as we aim to
                  keep only one free block. so "prev = curr;" line will run at least once
                  before this is run.
                */
                //remove the block from the all list
                prev->next = block->next;

                //remove the block from the free list
                prev = NULL;
                for (curr = pool->first_free_block; curr != NULL; curr = curr->next_free) {
                    if (curr == block) {
                        if (prev) {
                            prev->next = curr->next;
                        }
                        else {
                            /*There is no possible way that curr is both the first and last node in the list.
                              for this to run there must be at least one more free block. so there are more than
                              1 blocks in the pool. therefore there is no way for a node to be the first and the
                              last in the list.
                             */
                            pool->first_free_block = curr->next;
                        }
                    }
                    prev = curr;
                }
                free_block(block);
            }
            else {
                one_free_block = 1;
            }
        }
        prev = block;
    }
}


int mempool_is_full(const mempool_t *const pool)
{
    int result;
    if (pool == NULL)
        return 0;
    result = pool->first_free_block == NULL;
    return result;
}

size_t get_mempool_size(const mempool_t *const pool)
{
    size_t size = 0;
    if (pool == NULL)
        return -1;

    for (memblock_t *block = pool->all_blocks; block != NULL; block = block->next) {
        size += block->cell_count * pool->cell_size;
    }
    return size;
}

size_t mempool_get_capacity(const mempool_t * const pool)
{
    size_t capacity = 0;
    if (pool == NULL)
        return 0;

    for (const memblock_t * block = pool->all_blocks; block != NULL; block = block->next) {
        capacity += block->capacity;
    }
    return capacity;
}

size_t get_mempool_cell_size(const mempool_t *const pool)
{
    size_t cell_size = 0;
    if (pool == NULL)
        return 0;
    cell_size = pool->cell_size;
    return cell_size;
}

size_t get_mempool_cell_count(const mempool_t *const pool) {
    size_t cell_count = 0;
    if (pool == NULL)
        return 0;

    for (const memblock_t *block = pool->all_blocks; block != NULL; block = block->next) {
        cell_count += block->cell_count;
    }
    return cell_count;
}
