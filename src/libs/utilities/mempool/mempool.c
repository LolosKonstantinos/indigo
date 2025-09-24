//
// Created by Constantin on 22/09/2025.
//

#include "mempool.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct mempool {
    void *data;             //pointer to the allocated memory block
    size_t size;            //the size in bytes of the block

    void *first_free_cell;  //pointer to the first free cell

    size_t cell_count;      //the number of cells
    size_t cell_size;       //the size in bytes of each cell
    size_t capacity;        //the total number of free cells

    //global stats (pool + extensions)
    size_t total_size;        //the total size of the pool + extensions in bytes
    size_t total_capacity;    //the total amount of free cells
    size_t total_cell_count;  //the total amount of cells in pool + extensions

    struct memory_extension *next;   // in case we need to expand we create a new pool and link it like a linked list
};

struct memory_extension {
    void *data;
    size_t size;           //the size in bytes of the extension
    size_t cell_count;     //the number of cells in the extension
    size_t capacity;       //the number of free cells in the extension

    struct memory_extension *next;
};

mempool_t *new_mempool(size_t cell_count, size_t cell_size) {
    void *curr_cell, *next_cell;

    mempool_t *pool;

    if (cell_count == 0 || cell_size == 0) return NULL;

    //allocate the pool struct and the pool's memory
    pool = malloc(sizeof(mempool_t));
    if (pool == NULL) return NULL;


    if (cell_size < sizeof(void *)) cell_size = sizeof(void *);

    pool->data = malloc(cell_count * cell_size);
    if (pool->data == NULL) {
        free(pool);
        return NULL;
    }

    //initialize the pool members
    pool->size = cell_count * cell_size;
    pool->first_free_cell = pool->data;
    pool->cell_count = cell_count;
    pool->cell_size = cell_size;
    pool->capacity = cell_count;

    pool->total_size = pool->size;
    pool->total_capacity = pool->capacity;
    pool->total_cell_count = pool->cell_count;

    pool->next = NULL;


    //set up the free cell linked list
    for (size_t i = 0; i < cell_count - 1; i++) {
        curr_cell = pool->data + i * cell_size;
        next_cell = curr_cell + cell_size;

        memcpy(curr_cell,&next_cell,sizeof(void *));

    }
    //the last cell has NULL
    curr_cell = pool->data + (cell_count-1) * cell_size;
    next_cell = NULL;
    memcpy(curr_cell,&next_cell,sizeof(void *));

    return pool;
}

void free_mempool(mempool_t *pool) {
    memext_t *curr, *prev;
    if (pool == NULL) return;

    //free the pool data
    free(pool->data);

    //free the memory extensions
    curr = pool->next;
    while (curr != NULL ) {
        prev = curr;
        curr = curr->next;
        free(prev->data);
        free(prev);
    }

    //free the pool structure
    free(pool);
}

void *salloc(mempool_t *pool) {
    void *cell;

    if (pool == NULL) return NULL;
    if (pool->first_free_cell == NULL) {
        if (memextend(pool) != 0) return NULL;
    }
    cell = pool->first_free_cell;

    //find if the cell is in an extension or the main pool and adjust capacity
    if ((cell >= pool->data) && (cell < pool->data + pool->size))
        pool->capacity--;
    else {
        for (memext_t *ext = pool->next; ext != NULL; ext = ext->next) {
            if (cell >= ext->data && cell < ext->data + ext->size) {
                ext->capacity--;
                break;
            }
        }
    }
    pool->total_capacity--;

    //copy the address of the next cell to the free cell pointer
    memcpy(&(pool->first_free_cell), pool->first_free_cell, sizeof(void *));

    return cell;
}
//todo check for empty extensions and remove them
void sfree(mempool_t *pool, void *cell) {
    if (pool == NULL || cell == NULL) return;

    memcpy(cell,&(pool->first_free_cell), sizeof(void *));
    pool->first_free_cell = cell;

    pool->capacity--;
}

int memextend(mempool_t *pool) {
    memext_t *prev_ext = NULL, *ext = NULL;
    size_t ext_cell_count;
    void *cell = NULL, *next_cell = NULL;

    if (pool == NULL) return -1;

    for (prev_ext = pool->next; prev_ext->next != NULL; prev_ext = prev_ext->next){}

    prev_ext->next = malloc(sizeof(struct memory_extension));
    if (prev_ext->next == NULL) return 1;


    ext_cell_count = pool->cell_count / 2;
    if (ext_cell_count == 0) ext_cell_count = 1;

    ext = prev_ext->next;

    ext->data = malloc(ext_cell_count * pool->cell_size);
    if (ext->data == NULL) {
        free(ext);
        return 1;
    }


    ext->size = ext_cell_count * pool->cell_size;
    ext->cell_count = ext_cell_count;
    ext->capacity = ext_cell_count;
    ext->next = NULL;


    pool->total_capacity += ext_cell_count;

    for (size_t i = 0; i < ext_cell_count - 1; i++) {
        cell = ext->data + i * pool->cell_size;

        next_cell = cell + pool->cell_size;

        memcpy(cell, &next_cell, sizeof(void *));
    }
    cell = ext->data + (pool->cell_size * (ext_cell_count - 1));

    memcpy(cell, &(pool->first_free_cell), sizeof(void *));

    pool->first_free_cell = ext->data;

    return 0;
}

int is_empty(mempool_t *pool) {
    if (pool == NULL) return -1;

    return pool->capacity == 0;
}

size_t mempool_size(mempool_t *pool) {
    size_t size;

    if (pool == NULL) return -1;

    size = pool->size;
    for (memext_t *curr = pool->next; curr != NULL; curr = curr->next) {
        size += curr->size;
    }
    return size;
}

float get_capacity(mempool_t *pool) {
    size_t cell_count;
    if (pool == NULL) return 0;

    cell_count = pool->cell_count;
    for (memext_t *curr = pool->next; curr != NULL; curr = curr->next) {
        cell_count += curr->cell_count;
    }

    return (float)pool->total_capacity / (float)cell_count;
}