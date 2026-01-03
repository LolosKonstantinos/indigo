//
// Created by Constantin on 02/01/2026.
//

#ifndef BINARY_TREE_H
#define BINARY_TREE_H

#include <stdint.h>

typedef int(*cmp_f)(void *, void *);

typedef struct tree_priv_t tree_priv_t;
typedef struct tree_t tree_t;
typedef struct tree_node_t tree_node_t;

typedef int(*tree_insert)(tree_t, void *);
typedef int(*tree_remove)(tree_t, void *);
typedef int(*tree_search)(tree_t, void *);

struct tree_t{
    tree_insert  insert;
    tree_remove remove;
    tree_search search;
    tree_priv_t *priv;
};

typedef struct tree_attr {
    size_t data_size;
    cmp_f cmp;
}tree_attr_t;

int new_tree(tree_t *t, cmp_f cmp);
void free_tree(tree_t *t);
tree_node_t *new_node();

/*________________________________________AVL TREE FUNCTIONS________________________________________*/
//todo keep one of the 2
int avl_insert(tree_t* t, void* data);
int avl_insert_copy(tree_t *t, void* data);

int avl_delete(tree_t *t, void* data);

int avl_search(tree_t *t, void* data);

/*AVL HELPERS*/
tree_node_t** avl_balance(tree_node_t** stack, tree_node_t** top, tree_priv_t* tree);
#endif //BINARY_TREE_H
