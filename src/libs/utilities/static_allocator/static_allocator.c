//
// Created by Constantin on 22/09/2025.
//

#include "static_allocator.h"

#include <stdlib.h>
//todo: implement a linked list approach to expand the allocated memory

struct static_allocator {
    void *address; //the pointer to the first address of the memory blob
    size_t size; //number of bytes allocated

    size_t cell_count;// the number of cells
    size_t cell_size;//the size of each cell

    size_t next_available;//the index of a free cell ready to use
    unsigned char full;//if it is 1 then there is no more space to allocate
    size_t capacity; //the number of free cells;

    void *free_cells; //this array stores 1 bit per cell, if the cell's bit is 0 it is free if it's 1 then it's not
    size_t free_cells_size;
};

static_allocator *new_static_allocator(size_t cell_count, size_t cell_size) {
    static_allocator *alloc = malloc(sizeof(static_allocator));
    if (alloc == NULL) {
        return NULL;
    }

    alloc->address = malloc(cell_count * cell_size);
    if (alloc->address == NULL) {
        free(alloc);
        return NULL;
    }

    alloc->size = cell_count * cell_size;

    alloc->cell_count = cell_count;
    alloc->cell_size = cell_size;

    alloc->next_available = 0;
    alloc->full = 0;
    alloc->capacity = alloc->size;

    alloc->free_cells_size = (cell_count / 8) + 1;

    // we allocate 1 bit per cell, the +1 is to avoid rounding errors
    alloc->free_cells = calloc(alloc->free_cells_size, 1);
    if (alloc->free_cells == NULL) {
        free(alloc);
        return NULL;
    }

    return alloc;
}

void free_static_allocator(static_allocator *allocator) {
    free(allocator->address);
    free(allocator->free_cells);
    free(allocator);
}

void *salloc(static_allocator * restrict allocator) {
    size_t i, available_cell_byte;
    size_t current_byte;
    char j;

    if (allocator == NULL) return NULL;
    if (allocator->full) return NULL;

    available_cell_byte = (allocator->next_available / 8) + ((allocator->next_available % 8) > 0);
    current_byte = available_cell_byte;


    allocator->capacity--;
    ((unsigned char *)allocator->free_cells)[available_cell_byte] |= (unsigned char)(1<<(7-(allocator->next_available%8)));

    for (i = 0; i < allocator->free_cells_size; i++) {
        if (!((unsigned char *)allocator->free_cells)[current_byte]){
            for (j = 7; j >= 0; j--) {
                if ((!((unsigned char *)allocator->free_cells)[current_byte]) & 1<<j) {
                    allocator->next_available = (current_byte*8) -j;
                    break;
                }
            }
            break;
        }
        if (current_byte == allocator->cell_count - 1) current_byte = 0;
        else  current_byte++;
    }
    if (current_byte == available_cell_byte) allocator->full = 1;

    return allocator->address + (allocator->next_available * allocator->cell_size);
}

void sfree(static_allocator *allocator, void *ptr) {
    size_t cell, current_byte;

    if (allocator == NULL) return;
    if (ptr == NULL) return;
    if (ptr > allocator->address + allocator->size || ptr <= allocator->address) return;

    cell = (ptr - allocator->address)/allocator->cell_size;
    current_byte = (cell/ 8) + ((cell % 8) > 0);

    allocator->capacity++;
    ((unsigned char *)allocator->free_cells)[current_byte] &= ~(1<<(7-(cell % 8)));
}

int is_empty(static_allocator *allocator) {
    if (allocator == NULL) return -1;

    return allocator->capacity == 0;
}