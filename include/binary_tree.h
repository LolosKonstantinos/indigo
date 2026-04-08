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

#ifndef BINARY_TREE_H
#define BINARY_TREE_H

#include <stdint.h>

#define BINARY_TREE_TYPE_AVL 0
#define BINARY_TREE_TYPE_RED_BLACK 1

typedef int(*cmp_f)(void *, void *);
typedef void* (*usr_free_f)(void* node);

typedef struct tree_priv_t tree_priv_t;
typedef struct tree_t tree_t;
typedef struct tree_node_avl_t tree_node_t;

typedef int(*tree_insert)(tree_t *, void *);
typedef int(*tree_remove)(tree_t *, void *);
typedef int(*tree_search)(tree_t *, void *);
typedef int(*tree_search_pin)(tree_t *, void *, void **);
typedef int(*tree_search_release)(tree_t *);
struct tree_t{
    tree_insert  insert;
    tree_remove remove;
    tree_search search;
    //thread unsafe search function
    tree_search_pin search_pin;
    tree_search_release search_release;
    tree_priv_t *priv;
};

int new_tree(tree_t** t, cmp_f cmp, size_t data_size, char type);
void free_tree(tree_t *t);
tree_node_t *new_node();

/*________________________________________AVL TREE FUNCTIONS________________________________________*/
//todo keep one of the 2
int avl_insert(tree_t* t, void* data);
int avl_insert_copy(tree_t *t, void* data);

int avl_delete(tree_t *t, void* data);

int avl_search(tree_t* t, void* data);
int avl_search_pin(tree_t* t, void* data, void** ret_data);
int avl_search_release(tree_t* t);

/*AVL HELPERS*/
tree_node_t** avl_balance(tree_node_t** stack, tree_node_t** top, tree_priv_t* tree);
#endif //BINARY_TREE_H
