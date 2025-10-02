//
// Created by Constantin on 22/09/2025.
//

#include "mempool.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MEMPOOL_FLAG_LL 0x01
#define MEMPOOL_FLAG_BST 0x02
#define MEMPOOL_FLAG_EMPTY_EXTENSION 0x03

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

    uint16_t last_ext_handle; //the last handle assigned to an extension

    void *ext;//the root of an AVL tree of extensions or the first node of linked list
};

struct memory_extension_tree_node {
    void *data;

    void *first_free_cell;

    size_t cell_count;     //the number of cells in the extension
    size_t capacity;       //the number of free cells in the extension

    int32_t height;
    uint8_t lr;           //is it a left child or right child (left = 0 and right = 1)

    struct memory_extension_tree_node *left;
    struct memory_extension_tree_node *right;
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

    //initialize the universal functions
    pool->is_full = is_full;
    pool->get_capacity = get_capacity;
    pool->get_mempool_size = get_mempool_size;
    pool->get_cell_size = get_cell_size;

    //initialize the standard members
    //todo update
    private->cell_size = cell_size;
    private->cell_count = cell_count;
    private->capacity = cell_count;


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
    else if (attr->dynamic_pool_size) {
        if (attr->small_cell_size) {
            //supply the functions for the small cell size
        }
        else {
            pool->alloc = dalloc_default;
            pool->free = dfree_default;
            pool->extend = memextend_list_manual;
            pool->free_extension = free_extension_list_manual;

            private->first_free_cell = private->data;

            //create the free list
            for (size_t i = 0; i < cell_count - 1; i++) {
                curr_cell = private->data;
                next_cell = curr_cell + cell_size;

                memcpy(curr_cell, &next_cell, sizeof(void *));
            }
            curr_cell = private->data + (cell_count - 1) * cell_size;
            next_cell = NULL;
            memcpy(curr_cell, &next_cell, sizeof(void *));
        }
    }

    return pool;
}

void free_mempool(mempool_t *pool)  {
    ext_ll *curr, *prev;

    mempool_private_t *private;

    if (pool == NULL) return;

    private = pool->private;

    //free the pool data
    free(private->data);

    //free the memory extensions
    if (private->flags & MEMPOOL_FLAG_LL) {
        curr = private->ext;
        while (curr != NULL ) {
            prev = curr;
            curr = curr->next;
            free(prev->data);
            free(prev);
        }
    }
    else {

    }
    //free the pool structure
    free(private);
    free(pool);
}


void *dalloc_default(mempool_t *pool) {
    void *cell = NULL;
    mempool_private_t *private;
    ext_ll *ext;


    if (pool == NULL) return NULL;

    private = pool->private;

    if (private->first_free_cell == NULL)
        if (memextend_list(pool) != 0) return NULL;

    cell = private->first_free_cell;
    private->first_free_cell = *(void **)cell;

    //find the extension it belongs and adjust capacity
    ext = *(void **)cell;

    ext->capacity--;

    return cell;
}

void dfree_default(mempool_t *pool, void *cell) {
    ext_ll *ext, *temp_ext;
    mempool_private_t *private;
    uintptr_t data_addr;
    void *temp, *curr, *prev;
    if (pool == NULL || cell == NULL) return;

    private = pool->private;


    //find if the cell is in an extension or the main pool and adjust capacity

    //if the cell is in the pool
    if ((cell >= private->data) && (cell < private->data) ){
        private->capacity++;
        memcpy(cell,&(private->first_free_cell), sizeof(void *));
        private->first_free_cell = cell;
        return;
    }

    //then the cell is in an extension

    data_addr = (uintptr_t)cell & -(1<<private->alignment);
    ext = *(void **)data_addr;
    ext->capacity++;

    //add the cell to the end of the free list
    temp = NULL;
    memcpy(cell, &temp, sizeof(void *));
    memcpy(private->last_free_cell, &cell, sizeof(void *));

    //check to remove the extension
    if (ext->capacity == ext->cell_count) {
        if (private->flags & MEMPOOL_FLAG_EMPTY_EXTENSION) {
            remove_extension_list(pool, ext);
            return;
        }
        if (private->capacity > private->cell_count / 2) {
            remove_extension_list(pool, ext);
        }
        else private->flags |= MEMPOOL_FLAG_EMPTY_EXTENSION;
    }
}


void *salloc(mempool_t *pool) {
    void *cell;
    mempool_private_t *private;

    if (pool == NULL) return NULL;

    private = pool->private;

    if (private->first_free_cell == NULL)
        return NULL;

    if (private->first_free_cell == NULL) return NULL;

    cell = private->first_free_cell;

    //copy the address of the next cell to the free cell pointer
    memcpy(&(private->first_free_cell), private->first_free_cell, sizeof(void *));

    return cell;
}

void sfree(mempool_t *pool, void *cell) {
    mempool_private_t *private;

    if (pool == NULL || cell == NULL) return;

    private = pool->private;

    memcpy(cell,&(private->first_free_cell), sizeof(void *));
    private->first_free_cell = cell;

}


int memextend_list(mempool_t *pool) {
    size_t ext_cells, cell_count;
    mempool_private_t *private;

    ext_ll *ext;

    void *curr_cell, *next_cell;

    if (pool == NULL) return -1;
    private = pool->private;

    cell_count = get_cell_count(pool);

    ext_cells = private->growth_factor > 1 ?0 :cell_count  + (size_t)((double)cell_count * (private->growth_factor -1));
    if (ext_cells == 0) ext_cells = 1;
    if (ext_cells * private->cell_size > MEMPOOL_MAX_EXTENSION_SIZE)
        ext_cells = MEMPOOL_MAX_EXTENSION_SIZE / private->cell_size;

    if (ext_cells * private->cell_size > 1<<private->alignment)
        ext_cells = (1<<private->alignment) / private->cell_size;

    ext = malloc(sizeof(ext_ll));
    if (ext == NULL) return 1;

    ext->data = _aligned_malloc(ext_cells * private->cell_size + sizeof(void *), 1<<private->alignment);
    if (ext->data == NULL) {
        free(ext);
        return 1;
    }

    //write the extensions address to the start of the data buffer
    memcpy(ext->data, &ext, sizeof(void *));

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

    curr_cell = private->last_free_cell;
    *(void **)curr_cell = ext->data + sizeof(void *);

    return 0;
}

EXT_HANDLE memextend_list_manual(mempool_t* pool, size_t cell_count) {
    mempool_private_t *private;

    ext_ll *ext;

    void *curr_cell, *next_cell;

    if (pool == NULL) return NULL;
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

    //initialize the extenion
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

    curr_cell = private->last_free_cell;
    *(void **)curr_cell = ext->data + sizeof(void *);

    return ext->handle;
}

void free_extension_list_manual(mempool_t *pool, EXT_HANDLE handle) {
    mempool_private_t *private;
    ext_ll *temp_ext, *ext;
    void *curr, *prev;
    uintptr_t data_addr;

    if (pool == NULL || handle == NULL) return;

    private = pool->private;
    ext = handle;

    curr = private->first_free_cell;
    //handle the case where the first cell is in the extension to be removed
    while (curr != NULL ) {
        if ((curr >= private->data) && (curr < private->data) ) break;

        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext) private->first_free_cell = *(void **)curr;
        else break;

        curr = private->first_free_cell;
    }

    curr = private->first_free_cell;
    while (curr != NULL ) {
        prev = curr;
        curr = *(void **)curr;

        if (curr == NULL) break;

        if ((curr >= private->data) && (curr < private->data) ) {
            continue;
        }
        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext)
            *(void **)prev = *(void **)curr;
    }

    free(ext->data);
    free(ext);
}

void remove_extension_list(mempool_t *pool, ext_ll *ext) {
    mempool_private_t *private;
    ext_ll *temp_ext;
    void *curr, *prev;
    uintptr_t data_addr;

    if (pool == NULL || ext == NULL) return;

    private = pool->private;


    curr = private->first_free_cell;
    //handle the case where the first cell is in the extension to be removed
    while (curr != NULL ) {
        if ((curr >= private->data) && (curr < private->data) ) break;

        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext) private->first_free_cell = *(void **)curr;
        else break;

        curr = private->first_free_cell;
    }

    curr = private->first_free_cell;
    while (curr != NULL ) {
        prev = curr;
        curr = *(void **)curr;

        if (curr == NULL) break;

        if ((curr >= private->data) && (curr < private->data) ) {
            continue;
        }
        data_addr = (uintptr_t)curr & -(1<<private->alignment);
        temp_ext = *(void **)data_addr;

        if (temp_ext == ext)
            *(void **)prev = *(void **)curr;
    }

    free(ext->data);
    free(ext);
}


int memextend_tree(mempool_t *pool) {
    ext_tree *ext = NULL;
    size_t ext_cell_count;
    void *cell = NULL, *next_cell = NULL;

    mempool_private_t *private;

    if (pool == NULL) return -1;

    private = pool->private;

    ext = malloc(sizeof(struct memory_extension_tree_node));
    if (ext == NULL) return 1;


    ext_cell_count = (size_t)((double)get_cell_count(pool) * private->growth_factor);
    if (ext_cell_count == 0) ext_cell_count = 1;


    ext->data = malloc(ext_cell_count * private->cell_size);
    if (ext->data == NULL) {
        free(ext);
        return 1;
    }

    ext->first_free_cell = ext->data;
    ext->capacity = ext_cell_count;
    ext->left = NULL;
    ext->right = NULL;
    ext->cell_count = ext_cell_count;
    ext->height = 0;

    //attach to the pool extension tree
    insert_ext(pool, ext);


    //create the free cell linked list
    for (size_t i = 0; i < ext_cell_count - 1; i++) {
        cell = ext->data + i * private->cell_size;

        next_cell = cell + private->cell_size;

        memcpy(cell, &next_cell, sizeof(void *));
    }
    cell = ext->data + (private->cell_size * (ext_cell_count - 1));
    next_cell = NULL;
    memcpy(cell, &next_cell, sizeof(void *));

    return 0;
}

int insert_ext(mempool_t *pool, ext_tree *ext) {
    mempool_private_t *private;
    ext_tree *curr, *prev, *root, *a , *b, *c;
    //the stack for the tree traversal
    void **stack;
    uint32_t stack_nodes = 0;

    int bf;

    if (ext == NULL || pool == NULL) return -1;
    private = pool->private;


    if (private->ext == NULL) {
        private->ext = ext;
        return 0;
    }
    root = private->ext;

    stack = malloc(root->height * sizeof(void *));
    if (stack == NULL) {
        return 1;
    }


    //insert the node
    curr = private->ext;
    while (1) {
        prev = curr;
        ++curr->height;
        stack[stack_nodes++] = curr;
        if (ext->data < curr->data) {
            curr = curr->left;
            if (curr == NULL) {
                prev->left = ext;
                ext->lr = 0;
                break;
            }
            continue;
        }
        curr = curr->right;
        if (curr == NULL) {
            prev->right = ext;
            ext->lr = 1;
            break;
        }
    }

    //check for balance and fix imbalance

    while (stack_nodes > 0) {
        curr = stack[--stack_nodes];
        bf = curr->right->height - curr->left->height;
        if (abs(bf) > 1) {
            if (curr->lr == 0) {
                if (bf > 0) {
                    //left-right
                    a = curr;
                    b = curr->left;
                    c = b->right;


                    //rotate left at b
                    b->right = c->left;
                    c->left = b;

                    c->lr = b->lr;
                    b->lr = 0;

                    c->lr ? a->right = c: a->left = c;

                    if (b->left == NULL) {
                        if (b->right == NULL)
                            b->height = 0;
                        else
                            b->height = b->right->height + 1;
                    }
                    else {
                        if (b->right == NULL)
                            b->height = b->left->height + 1;
                        else {
                            b->height = b->right->height > b->left->height ? b->right->height+ 1 : b->left->height + 1;
                        }
                    }

                    if (c->left == NULL) {
                        if (c->right == NULL)
                            c->height = 0;
                        else
                            c->height = c->right->height + 1;
                    }
                    else {
                        if (c->right == NULL)
                            c->height = c->left->height + 1;
                        else {
                            c->height = c->right->height > c->left->height ? c->right->height+ 1 : c->left->height + 1;
                        }
                    }

                    //rotate right at a
                    b = c;

                    a->left = b->right;
                    b->right = a;

                    b->lr = a->lr;
                    a->lr = 1;

                    //attach b to the previous node
                    curr = stack[stack_nodes - 1];
                    b->lr ? curr->right = b : curr->left = b;

                }
                else {
                    //left-left
                    a = curr;
                    b = curr->left;

                    a->left = b->right;
                    b->right = a;

                    b->lr = a->lr;
                    a->lr = 1;

                    //attach b to the previous node
                    curr = stack[stack_nodes - 1];
                    b->lr ? curr->right = b : curr->left = b;
                }
            }
            else {
                if (bf < 0) {
                    //right-left
                    a = curr;
                    b = curr->right;
                    c = b->left;

                    //rotate right at b
                    b->left = c->right;
                    c->right = b;

                    c->lr = b->lr;
                    b->lr = 1;

                    c->lr ? a->right = c: a->left = c;

                    if (b->left == NULL) {
                        if (b->right == NULL)b->height = 0;
                        else b->height = b->right->height + 1;
                    }
                    else {
                        if (b->right == NULL)b->height = b->left->height + 1;
                        else b->height = b->right->height > b->left->height ? b->right->height+ 1 : b->left->height + 1;
                    }

                    if (c->left == NULL) {
                        if (c->right == NULL)c->height = 0;
                        else c->height = c->right->height + 1;
                    }
                    else {
                        if (c->right == NULL)c->height = c->left->height + 1;
                        else c->height = c->right->height > c->left->height ? c->right->height+ 1 : c->left->height + 1;
                    }

                    //rotate left at a
                    b = c;

                    a->right = b->left;
                    b->left = a;

                    b->lr = a->lr;
                    a->lr = 0;

                    curr = stack[stack_nodes - 1];
                    b->lr ? curr->right = b : curr->left = b;

                }
                else {
                    //right-right
                    a = curr;
                    b = curr->right;

                    a->right = b->left;
                    b->left = a;

                    b->lr = a->lr;
                    a->lr = 0;

                    curr = stack[stack_nodes - 1];
                    b->lr ? curr->right = b : curr->left = b;
                }
            }
            //update heights
            if (a->left == NULL) {
                if (a->right == NULL)
                    a->height = 0;
                else
                    a->height = a->right->height + 1;
            }
            else {
                if (a->right == NULL)
                    a->height = a->left->height + 1;
                else {
                    a->height = a->right->height > a->left->height ? a->right->height+ 1 : a->left->height + 1;
                }
            }

            if (b->left == NULL) {
                if (b->right == NULL)
                    b->height = 0;
                else
                    b->height = b->right->height + 1;
            }
            else {
                if (b->right == NULL)
                    b->height = b->left->height + 1;
                else {
                    b->height = b->right->height > b->left->height ? b->right->height+ 1 : b->left->height + 1;
                }
            }
        }
    }
    free(stack);
    return 0;
}


int is_full(const mempool_t *pool) {
    return 0;
}

size_t get_mempool_size(const mempool_t *pool) {
    if (pool == NULL) return -1;

    return  0;
}

float get_capacity(const mempool_t *pool) {
    if (pool == NULL) return 0;

    return 1;
}

size_t get_cell_size(const mempool_t *pool) {
    if (pool == NULL) return 0;
    return 1;
}

size_t get_cell_count(const mempool_t *pool) {
    if (pool == NULL) return 0;
    return 1;
}