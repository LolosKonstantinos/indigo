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

#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdalign.h>

#define MEMPOOL_MAX_SIZE (1<<30) //limit pool size to 1 GiB
#define MEMPOOL_MAX_EXTENSION_SIZE (1<<30) //limit each extension to 1 GiB

typedef struct mempool_t mempool_t;

typedef void *(*alloc_fn)(mempool_t *);
typedef void (*dealloc_fn)(mempool_t *, void *);
typedef void (*optimize_fn)(mempool_t *);


//init and destroy functionalities
#define new_mempool(cell_count, type, attr_pointer) new_mempool_manual(cell_count, sizeof(type), alignof(type),attr_pointer)
//#define new_mempool(mempool) (mempool_attr*)malloc(sizeof(mempool_attr))
mempool_t *new_mempool_manual(size_t cell_count, size_t cell_size, int16_t cell_alignment, float growth_rate);
void free_mempool(mempool_t * pool);

//allocators and deallocators

//default dynamic pool
void *mempool_dalloc(mempool_t *pool);
//static pool
void *mempool_salloc(mempool_t *pool);
void mempool_free(mempool_t *pool, void *cell);

//extension utilities
int memextend_pool(mempool_t *pool);
void optimize_mempool(mempool_t *pool);

//universal utilities
int mempool_is_full(const mempool_t * pool);
size_t mempool_get_capacity(const mempool_t * pool);
size_t get_mempool_size(const mempool_t *pool);
size_t get_mempool_cell_size(const mempool_t *pool);
size_t get_mempool_cell_count(const mempool_t *pool);

#endif //MEMPOOL_H
