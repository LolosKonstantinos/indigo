//
// Created by Constantin on 22/09/2025.
//

#include "mempool.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define MEMPOOL_FLAG_LL 0x01
#define MEMPOOL_FLAG_EMPTY_EXTENSION 0x02

struct mempool_private {
    void *data;             //pointer to the allocated memory block

    void *first_free_cell;  //pointer to the first free cell
    void *last_free_cell;   //pointer to the last free cell (used only with linked list)

    size_t cell_count;      //the number of cells
    size_t cell_size;       //the size in bytes of each cell
    size_t capacity;        //the total number of free cells
    float growth_factor;    //the factor that determines the next extension's size.
                            //< 1 decreasing, 1 static, > 1 increasing size
                            //(example: x1.5 factor doubles the size of the pool)

    uint8_t alignment;      //the power of 2 of the alignment
                            //for growth factor <= 1, allows constant time free, for any number of extensions

    uint8_t flags;         //flag attributes for the pool


    void *ext;//the root of an AVL tree of extensions or the first node of linked list
};

struct memory_extension_ll_node {
    void *data;

    void *first_free_cell;

    EXT_HANDLE handle;     //a handle to identify the extension, will probably be a pointer to the extension

    size_t cell_count;     //the number of cells in the extension
    size_t capacity;       //the number of free cells in the extension

    struct memory_extension_ll_node *next;
};

mempool_t *new_mempool(const size_t cell_count, size_t cell_size, const mempool_attr* const attr) {
    void *curr_cell, *next_cell;

    mempool_t *pool;
    mempool_private_t *private;

    if (cell_count == 0 || cell_size == 0) return NULL;
    if (cell_size < sizeof(void *)) {
        cell_size = sizeof(void *);
    }

    //allocate the pool struct and the pool's memory

    pool = malloc(sizeof(mempool_t));
    if (pool == NULL) return NULL;

    private = malloc(sizeof(mempool_private_t));
    if (private == NULL) {
        free(pool);
        return NULL;
    }
    pool->private = private;



    private->data = malloc(cell_count * cell_size);
    if (private->data == NULL) {
        free(private);
        free(pool);
        return NULL;
    }

    //initialize the mutex
    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->cond, NULL);

    //initialize the universal functions
    pool->get_capacity = get_capacity;

    //initialize the standard members
    private->cell_size = cell_size;
    private->cell_count = cell_count;
    private->capacity = cell_count;
    private->ext = NULL;


    if (!attr) {
        //the default configuration
        pool->alloc = salloc;
        pool->free = sfree;
        pool->extend = NULL;
        pool->free_extension = NULL;

        private->alignment = (uint8_t)ceil(log2((double)(cell_count * cell_size)));
        private->first_free_cell = private->data;

        //create the free list
        for (size_t i = 0; i < cell_count - 1; i++) {
            curr_cell = private->data + i * cell_size;
            next_cell = curr_cell + cell_size;

            memcpy(curr_cell, &next_cell, sizeof(void *));
        }
        curr_cell = private->data + (cell_count - 1) * cell_size;
        next_cell = NULL;
        memcpy(curr_cell, &next_cell, sizeof(void *));
    }
    else if (attr->dynamic_pool) {
        pool->alloc = dalloc;
        pool->free = dfree;
        pool->extend = memextend_list_manual;
        pool->free_extension = free_extension_list_manual;

        private->first_free_cell = private->data;
        private->growth_factor = attr->growth_factor;
        private->flags = MEMPOOL_FLAG_LL;

        //create the free list
        for (size_t i = 0; i < cell_count - 1; i++) {
            curr_cell = private->data + i * cell_size;
            next_cell = curr_cell + cell_size;

            memcpy(curr_cell, &next_cell, sizeof(void *));
        }
        curr_cell = private->data + (cell_count - 1) * cell_size;
        next_cell = NULL;
        memcpy(curr_cell, &next_cell, sizeof(void *));

        private->last_free_cell = curr_cell;

    }
    else if (!attr->dynamic_pool) {
        pool->alloc = salloc;
        pool->free = sfree;
        pool->extend = NULL;
        pool->free_extension = NULL;


        private->alignment = (uint8_t)ceil(log2((double)(cell_count * cell_size)));
        private->first_free_cell = private->data;
        private->flags = 0;

        //create the free list
        for (size_t i = 0; i < cell_count - 1; i++) {
            curr_cell = private->data + i * cell_size;
            next_cell = curr_cell + cell_size;

            memcpy(curr_cell, &next_cell, sizeof(void *));
        }
        curr_cell = private->data + (cell_count - 1) * cell_size;
        next_cell = NULL;
        memcpy(curr_cell, &next_cell, sizeof(void *));
    }

    return pool;
}

void free_mempool(mempool_t *pool)  {
    ext_ll *curr, *prev;

    mempool_private_t *private;

    if (pool == NULL) return;
    pthread_mutex_lock(&pool->mutex);

    private = pool->private;

    //free the pool data
    free(private->data);

    //free the memory extensions
    if (private->flags & MEMPOOL_FLAG_LL) {
        curr = private->ext;
        while (curr != NULL ) {
            prev = curr;
            curr = curr->next;
            _aligned_free(prev->data);
            free(prev);
        }
    }

    //free the pool structure
    free(private);
    pthread_mutex_unlock(&pool->mutex);

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond);
    free(pool);

}


void *dalloc(mempool_t *pool) {
    void *cell = NULL;
    mempool_private_t *private;
    ext_ll *ext;
    uintptr_t data_addr;


    if (pool == NULL) return NULL;
    pthread_mutex_lock(&pool->mutex);

    private = pool->private;

    //if there is no available space then we extend the pool
    if (private->first_free_cell == NULL)
        if (memextend_list(pool) != 0) return NULL;

    cell = private->first_free_cell;
    private->first_free_cell = *(void **)cell;
    if (private->first_free_cell == NULL) private->last_free_cell = NULL;

    //find the extension it belongs and adjust capacity
    if ((cell >= private->data) && (cell < private->data + private->cell_count * private->cell_size)) {
        private->capacity--;
    }
    else {
        data_addr = (uintptr_t)cell & -(1<<private->alignment);
        ext = *(void **)data_addr;
        ext->capacity--;
    }
    pthread_mutex_unlock(&pool->mutex);
    return cell;
}

void dfree(mempool_t *pool, void *cell) {
    ext_ll *ext;
    mempool_private_t *private;
    uintptr_t data_addr;
    if (pool == NULL || cell == NULL) return;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;

    //update the last_free_cell in edge case
    if (private->first_free_cell == NULL) {
        private->last_free_cell = cell;
    }
    //find if the cell is in an extension or the main pool and adjust capacity

    //if the cell is in the pool
    if ((cell >= private->data) && (cell < private->data + private->cell_count * private->cell_size)) {
        memcpy(cell,&(private->first_free_cell), sizeof(void *));
        private->first_free_cell = cell;
        private->capacity++;
        return;
    }

    //then the cell is in an extension
    data_addr = (uintptr_t)cell & -(1<<private->alignment);
    ext = *(void **)data_addr;
    ext->capacity++;

    //add the cell to the end of the free list
    *(void **)cell = NULL;
    if (private->last_free_cell != NULL) {
        memcpy(private->last_free_cell, &cell, sizeof(void *));
    }
    else {
        private->first_free_cell = cell;
    }
    private->last_free_cell = cell;

    //check to remove the extension
    if (ext->capacity == ext->cell_count) {
        if (private->flags & MEMPOOL_FLAG_EMPTY_EXTENSION) {
            remove_extension_list(pool, ext);
            return;
        }
        if (private->capacity > private->cell_count / 2) { //todo change to 80%
            remove_extension_list(pool, ext);
        }
        else private->flags |= MEMPOOL_FLAG_EMPTY_EXTENSION;
    }
    pthread_mutex_unlock(&pool->mutex);
}


void *salloc(mempool_t *pool) {
    void *cell;
    mempool_private_t *private;

    if (pool == NULL) return NULL;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;

    if (private->first_free_cell == NULL)
        return NULL;

    if (private->first_free_cell == NULL) return NULL;

    cell = private->first_free_cell;

    //copy the address of the next cell to the free cell pointer
    memcpy(&(private->first_free_cell), private->first_free_cell, sizeof(void *));

    private->capacity++;

    pthread_mutex_unlock(&pool->mutex);

    return cell;
}

void sfree(mempool_t *pool, void *cell) {
    mempool_private_t *private;

    if (pool == NULL || cell == NULL) return;
    pthread_mutex_lock(&pool->mutex);
    private = pool->private;

    memcpy(cell,&(private->first_free_cell), sizeof(void *));
    private->first_free_cell = cell;
    private->capacity--;

    pthread_mutex_unlock(&pool->mutex);
}


int memextend_list(mempool_t *pool) {
    size_t ext_cells, cell_count;
    mempool_private_t *private;

    ext_ll *ext;

    void *curr_cell, *next_cell;

    if (pool == NULL) return -1;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;

    cell_count = get_cell_count(pool);

    //calculate the new size
    ext_cells = (private->growth_factor > 1 ?0 :cell_count)+(size_t)((double)cell_count * (private->growth_factor -1));
    if (ext_cells == 0) ext_cells = 1;
    if (ext_cells * private->cell_size > MEMPOOL_MAX_EXTENSION_SIZE)
        ext_cells = MEMPOOL_MAX_EXTENSION_SIZE / private->cell_size;

    if (ext_cells * private->cell_size > 1<<private->alignment)
        ext_cells = (1<<private->alignment) / private->cell_size;

    //allocate the extension and the buffer
    ext = malloc(sizeof(ext_ll));
    if (ext == NULL) return 1;

    ext->data = _aligned_malloc(ext_cells * private->cell_size + sizeof(void *), 1<<private->alignment);
    if (ext->data == NULL) {
        free(ext);
        return 1;
    }

    //write the extensions address to the start of the data buffer
    memcpy(ext->data, &ext, sizeof(void *));

    //attach the extension to the linked list
    ext->next = private->ext;
    private->ext = ext;

    ext->first_free_cell = ext->data + sizeof(void *);
    ext->capacity = ext_cells;
    ext->handle = NULL;
    ext->cell_count = ext_cells;


    //create the cell free ll
    //write the addr of the first cell to the last cell of the private->last_free_cell

    for (size_t i = 0; i < ext_cells-1; i++) {
        curr_cell = ext->data + sizeof(void *) + i * private->cell_size;
        next_cell = curr_cell + private->cell_size;
        *(void **)curr_cell = next_cell;
    }

    curr_cell = ext->data + sizeof(void *) + (ext_cells - 1) * private->cell_size;
    *(void **)curr_cell = NULL;

    //attach to the free list
    if (private->first_free_cell == NULL) {
        private->first_free_cell = ext->data + sizeof(void *);
        private->last_free_cell = ext->data + sizeof(void *) + (ext_cells - 1) * private->cell_size;
        return 0;
    }
    curr_cell = private->last_free_cell;
    *(void **)curr_cell = ext->data + sizeof(void *);
    private->last_free_cell = ext->data + sizeof(void *) + (ext_cells - 1) * private->cell_size;

    pthread_mutex_unlock(&pool->mutex);

    return 0;
}

EXT_HANDLE memextend_list_manual(mempool_t* pool, size_t cell_count) {
    mempool_private_t *private;

    ext_ll *ext;

    void *curr_cell, *next_cell;

    if (pool == NULL) return NULL;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;



    if (cell_count == 0) cell_count = 1;

    if (cell_count * private->cell_size > MEMPOOL_MAX_EXTENSION_SIZE)
        cell_count = MEMPOOL_MAX_EXTENSION_SIZE / private->cell_size;

    if (cell_count * private->cell_size > 1<<private->alignment)
        cell_count = (1<<private->alignment) / private->cell_size;

    ext = malloc(sizeof(ext_ll));
    if (ext == NULL) return NULL;

    ext->data = _aligned_malloc(cell_count * private->cell_size + sizeof(void *), 1<<private->alignment);
    if (ext->data == NULL) {
        free(ext);
        return NULL;
    }

    //write the extensions address to the start of the data buffer
    memcpy(ext->data, &ext, sizeof(void *));

    //attach the extension to the pool
    ext->next = private->ext;
    private->ext = ext;

    //initialize the extension
    ext->first_free_cell = ext->data + sizeof(void *);
    ext->capacity = cell_count;
    ext->handle = ext;
    ext->cell_count = cell_count;


    //create the cell free ll
    //write the addr of the first cell to the last cell of the private->last_free_cell

    for (size_t i = 0; i < cell_count-1; i++) {
        curr_cell = ext->data + sizeof(void *) + i * private->cell_size;
        next_cell = curr_cell + private->cell_size;
        *(void **)curr_cell = next_cell;
    }

    curr_cell = ext->data + sizeof(void *) + (cell_count - 1) * private->cell_size;
    *(void **)curr_cell = NULL;

    if (private->first_free_cell == NULL) {
        private->first_free_cell = ext->data + sizeof(void *);
        private->last_free_cell = ext->data + sizeof(void *) + (cell_count - 1) * private->cell_size;
        return ext->handle;
    }

    curr_cell = private->last_free_cell;
    *(void **)curr_cell = ext->data + sizeof(void *);
    private->last_free_cell = ext->data + sizeof(void *) + (cell_count - 1) * private->cell_size;

    pthread_mutex_unlock(&pool->mutex);
    return ext->handle;
}

void free_extension_list_manual(mempool_t *pool, EXT_HANDLE handle) {
    mempool_private_t *private;
    ext_ll *temp_ext, *ext;
    void *curr, *prev;
    uintptr_t data_addr;

    if (pool == NULL || handle == NULL) return;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;
    ext = handle;

    curr = private->first_free_cell;
    //handle the case where the first cell is in the extension to be removed
    while (curr != NULL ) {
        if ((curr >= private->data) && (curr < private->data + private->cell_count * private->cell_size)) break;

        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext) private->first_free_cell = *(void **)curr;
        else break;

        curr = private->first_free_cell;
        if (curr == NULL) {
            private->last_free_cell = NULL;
        }
        else if (*(void **)curr == NULL) {
            private->last_free_cell = curr;
        }
    }

    curr = private->first_free_cell;
    while (curr != NULL ) {
        prev = curr;
        curr = *(void **)curr;

        if (curr == NULL) break;

        if ((curr >= private->data) && (curr < private->data + private->cell_count * private->cell_size)) {
            continue;
        }
        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext) {
            *(void**)prev = *(void**)curr;
            if (*(void **)prev == NULL) {
                private->last_free_cell = prev;
            }
            curr = prev;
        }
    }

    _aligned_free(ext->data);
    free(ext);
    pthread_mutex_unlock(&pool->mutex);
}

void remove_extension_list(mempool_t *pool, ext_ll *ext) {
    mempool_private_t *private;
    ext_ll *temp_ext;
    void *curr, *prev;
    uintptr_t data_addr;

    if (pool == NULL || ext == NULL) return;

    pthread_mutex_lock(&pool->mutex);

    private = pool->private;


    curr = private->first_free_cell;
    //handle the case where the first cell is in the extension to be removed
    while (curr != NULL ) {
        if ((curr >= private->data) && (curr < private->data + private->cell_count * private->cell_size)) break;

        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext) private->first_free_cell = *(void **)curr;
        else break;

        curr = private->first_free_cell;
        if (curr == NULL) {
            private->last_free_cell = NULL;
        }
        else if (*(void **)curr == NULL) {
            private->last_free_cell = curr;
        }
    }

    curr = private->first_free_cell;
    while (curr != NULL ) {
        prev = curr;
        curr = *(void **)curr;

        if (curr == NULL) break;

        if ((curr >= private->data) && (curr < private->data + private->cell_count * private->cell_size)) {
            continue;
        }
        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext){
            *(void **)prev = *(void **)curr;
            if (*(void **)prev == NULL) {
                private->last_free_cell = prev;
            }
            curr = prev;
        }
    }

    _aligned_free(ext->data);
    free(ext);

    pthread_mutex_unlock(&pool->mutex);
}

int is_full(mempool_t* pool) {
    int result;
    if (pool == NULL) return 0;
    pthread_mutex_lock(&pool->mutex);
    mempool_private_t *private = pool->private;
    result = private->first_free_cell == NULL;
    pthread_mutex_unlock(&pool->mutex);
    return result;
}

size_t get_mempool_size(mempool_t *pool) {
    size_t size = 0;
    mempool_private_t *private;
    if (pool == NULL) return -1;
    pthread_mutex_lock(&pool->mutex);
    private = pool->private;
    size += private->cell_count * private->cell_size;
    for (ext_ll *ext = private->ext; ext != NULL; ext = ext->next) {
        size += ext->cell_count * private->cell_size;
    }
    pthread_mutex_unlock(&pool->mutex);
    return  size;
}

size_t get_capacity(mempool_t* pool) {
    size_t capacity = 0;
    mempool_private_t *private;
    if (pool == NULL) return 0;
    pthread_mutex_lock(&(pool->mutex));
    private = pool->private;
    capacity = private->capacity;
    for (ext_ll *ext = private->ext; ext != NULL; ext = ext->next) {
        capacity += ext->capacity;
    }
    pthread_mutex_unlock(&pool->mutex);
    return capacity;
}

size_t get_cell_size(mempool_t *pool) {
    mempool_private_t *private;
    size_t cell_size = 0;
    if (pool == NULL) return 0;
    pthread_mutex_lock(&pool->mutex);
    private = pool->private;
    cell_size = private->cell_size;
    pthread_mutex_unlock(&pool->mutex);
    return cell_size;
}

size_t get_cell_count(mempool_t *pool) {
    size_t cell_count = 0;
    mempool_private_t *private;
    if (pool == NULL) return 0;
    pthread_mutex_lock(&pool->mutex);
    private = pool->private;

    cell_count = private->cell_count;
    for (ext_ll *ext = private->ext; ext != NULL; ext = ext->next) {
        cell_count += ext->cell_count;
    }
    pthread_mutex_unlock(&pool->mutex);
    return cell_count;
}