//
// Created by Constantin on 22/09/2025.
//

#ifndef STATIC_ALLOCATOR_H
#define STATIC_ALLOCATOR_H
#include <stddef.h>

typedef struct static_allocator static_allocator;

static_allocator *new_static_allocator(size_t cell_count, size_t cell_size);
void free_static_allocator(static_allocator *allocator);

void *salloc(static_allocator * restrict allocator);
void sfree(static_allocator *allocator, void *ptr);

int is_empty(static_allocator *allocator);

#endif //STATIC_ALLOCATOR_H
