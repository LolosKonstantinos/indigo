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

#include "binary_tree.h"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define FORCE_INLINE inline __attribute__((always_inline))
#define TREE_RIGHT (1)
#define TREE_ROOT (0)
#define TREE_LEFT (-1)

#define GET_HEIGHT(node) \
((node)->right?\
    ( (node)->left?\
        (1 + (((node)->right->height > (node)->left->height)?(node)->right->height:(node)->left->height)):\
((node)->right->height+1) ):\
    ( (node)->left?((node)->left->height+1) : 1)\
)


struct tree_priv_t {
    pthread_mutex_t mutex;
    tree_node_t *root;
    size_t data_size;
    cmp_f cmp;          // the function based on which we do struct comparison
    usr_free_f node_free; //user defined free, to free node data. Can be null if free() is ok.
    uint32_t height;
    unsigned char zero[4];
};

//the direction and balance factor fields are kinda useless,
//but whether we remove them or not the node is the same size

struct tree_node_avl_t {
    void *data;
    tree_node_t *left;
    tree_node_t *right;
    uint32_t height;
    int32_t bf;
};


int new_tree(tree_t **t, const cmp_f cmp, const size_t data_size, const char type) {
    tree_t *temp;
    tree_priv_t *priv;

    if (!t || !cmp || !data_size) {
        return -1;
    }

    temp = malloc(sizeof(tree_t));
    if (!temp) {
        *t = NULL;
        return 1;
    }
    priv = calloc(1, sizeof(tree_priv_t));
    if (!priv) {
        free(temp);
        *t = NULL;
        return 1;
    }

    priv->cmp = cmp;
    priv->root = NULL;
    priv->data_size = data_size;
    pthread_mutex_init(&(priv->mutex), NULL);

    temp->priv = priv;
    if (type == BINARY_TREE_TYPE_AVL) {
        temp->search = avl_search;
        temp->remove = avl_delete;
        temp->insert = avl_insert_copy;
        temp->search_pin = avl_search_pin;
        temp->search_release = avl_search_release;
    }
    else if (type == BINARY_TREE_TYPE_RED_BLACK) {
        printf("to be implemented");
    }
    else {
        free(temp);
        free(priv);
        *t = NULL;
        return 1;
    }
    *t = temp;
    return 0;
}
void free_tree(tree_t *t) {
    tree_priv_t *priv;
    tree_node_t **stack;
    tree_node_t **top;
    tree_node_t *temp;
    if (!t) return;
    priv = t->priv;

    stack = (tree_node_t **)malloc(sizeof(tree_node_t *) * (priv->height + 2));
    top = stack - 1;

    *(++top) = priv->root;
    while (top >= stack) {
        temp = *(top--);
        if (temp->left) *(++top) = temp->left;
        if (temp->right) *(++top) = temp->right;
        free(temp->data);
        free(temp);
    }
    pthread_mutex_destroy(&priv->mutex);
    free(priv);
    free((void *)stack);
}

tree_node_t *new_node() {
    tree_node_t *node = calloc(1,sizeof(tree_node_t));
    if(!node) return NULL;

    //new nodes are inserted as leaves so their height is 1, 0 is not valid
    node->height = 1;

    return node;
}

/*________________________________________AVL TREE FUNCTIONS________________________________________*/
int avl_insert(tree_t* t, void* data) {
    tree_priv_t *priv;
    tree_node_t *node;
    tree_node_t *temp;
    tree_node_t **stack = NULL;
    tree_node_t **top;
    int cmp_res;

    if (!t) return -1;
    if (!(t->priv)) return -1;

    pthread_mutex_lock(&(t->priv->mutex));
    priv = t->priv;

    node = new_node();
    if (!node) {
        pthread_mutex_unlock(&(priv->mutex));
        return 1;
    }

    stack = malloc(sizeof(tree_node_t *) * (priv->height + 2));
    if (!stack) {
        pthread_mutex_unlock(&(priv->mutex));
        free(node);
        return 1;
    }
    top = stack - 1;

    if (!priv->root) {
        node->data = data;
        priv->root = node;
        pthread_mutex_unlock(&(priv->mutex));
        free(stack);
        return 0;
    }

    temp = priv->root;

    while (1) {
        cmp_res = priv->cmp(data, temp->data);
        if (cmp_res == 0) {
            pthread_mutex_unlock(&(priv->mutex));
            //if the node already exists we do not re-insert it
            free(node);
            free(stack);
            return 0;
        }

        //add the current node to the stack, so that after the insertion we have the stack trace of the new node
        *(++top) = temp;

        if (cmp_res > 0) {
            if (temp->right == NULL) {
                temp->right = node;
                break;
            }
            temp = temp->right;
        }
        else {
            if (temp->left == NULL) {
                temp->left = node;
                break;
            }
            temp = temp->left;
        }
    }

    node->data = data;

    avl_balance(stack, top, priv);

    pthread_mutex_unlock(&(priv->mutex));
    free(stack);
    return 0;
}

int avl_insert_copy(tree_t *t, void* data) {
    tree_priv_t *priv;
    tree_node_t *node;
    tree_node_t *temp;
    tree_node_t **stack = NULL;
    tree_node_t **top;
    int cmp_res;

    if (!t) return -1;
    if (!(t->priv)) return -1;

    pthread_mutex_lock(&(t->priv->mutex));
    priv = t->priv;

    //create the node we will insert
    node = new_node();
    if (!node) {
        pthread_mutex_unlock(&(priv->mutex));
        return 1;
    }

    //allocate the data field of the node
    node->data = calloc(1,priv->data_size);
    if (!node->data) {
        pthread_mutex_unlock(&(priv->mutex));
        free(node);
        return 1;
    }
    //copy the data to the node
    memcpy(node->data, data, priv->data_size);

    //allocate the stack we will use to remember the path we followed in the tree to insert the node
    stack = malloc(sizeof(tree_node_t *) * (priv->height + 2));
    if (!stack) {
        pthread_mutex_unlock(&(priv->mutex));
        free(node->data);
        free(node);
        return 1;
    }
    top = stack - 1;

    //if there is no root, the tree is empty, insertion is just putting the node as root
    if (!priv->root) {
        priv->root = node;
        priv->height = 1;
        pthread_mutex_unlock(&(priv->mutex));
        free(stack);
        return 0;
    }

    temp = priv->root;

    while (1) {
        //compare the data to the current node's data
        cmp_res = priv->cmp(data, temp->data);

        //if the node already exists we do not re-insert it
        if (cmp_res == 0) {
            pthread_mutex_unlock(&(priv->mutex));
            free(node->data);
            free(node);
            free(stack);
            return 0;
        }

        //add the current node to the stack, so that after the insertion we have the stack trace of the new node
        *(++top) = temp;

        //move down the tree
        if (cmp_res > 0) {
            if (temp->right == NULL) {
                temp->right = node;
                break;
            }
            temp = temp->right;
        }
        else {
            if (temp->left == NULL) {
                temp->left = node;
                break;
            }
            temp = temp->left;
        }
    }

    avl_balance(stack, top, priv);
    priv->height = priv->root->height;

    pthread_mutex_unlock(&(priv->mutex));
    free(stack);
    return 0;
}

//todo: this function fails to remove nodes after the first is removed, it causes segfault
int avl_delete(tree_t *t, void* data) {
    tree_priv_t *priv;
    tree_node_t *node;
    tree_node_t *prev = NULL;
    tree_node_t *temp;
    tree_node_t *temp_prev;
    tree_node_t **stack = NULL;
    tree_node_t **top;
    char direction = TREE_ROOT;
    char temp_direction;
    int cmp_res;
    cmp_f cmp;

    if (!(t && data)) return -1;

    pthread_mutex_lock(&(t->priv->mutex));
    priv = t->priv;
    node = priv->root;
    cmp = priv->cmp;

    stack = malloc(priv->height * sizeof(tree_node_t *));
    if (!stack) {
        pthread_mutex_unlock(&(priv->mutex));
        return -1;
    }
    top = stack - 1; //so, when we push for the first time the top pointer points to the top element and not above it

    //find the node and create a stack trace
    while (node != NULL) {
        //compare
        cmp_res = cmp(data, node->data);
        if (cmp_res == 0) break;

        //add to the stack
        *(++top) = node;

        prev = node;

        if (cmp_res < 0) {
            node = node->left;
            direction = TREE_LEFT;
        }
        else {
            node = node->right;
            direction = TREE_RIGHT;
        }
    }

    //the node was not found in the tree
    if (!node) {
        pthread_mutex_unlock(&(priv->mutex));
        free(stack);
        return 1;
    }

    //delete the node (based on the children it has)
    if (!(node->left || node->right)) {
        //if it has no children
        if (!prev || direction == TREE_ROOT) {
            priv->root = NULL;
            priv->height = 0;
        }
        else if (direction == TREE_LEFT) {
            prev->left = NULL;
        }
        else{
            prev->right = NULL;
        }
    }
    else if (node->left && node->right) {
        //if it has both children

        //we favor the tallest subtree, so that the resulting tree is more balanced
        //we find the node that will replace the deleted node

        {//we open a new code block to create a new temporary stack
            tree_node_t** temp_top;

            temp_top = top + 1;

            //find the replacement node
            temp_prev = node;
            if (node->left->height > node->right->height) {
                temp = node->left;
                *(++temp_top) = temp;
                temp_direction = TREE_LEFT;
                while (temp->right) {
                    temp_prev = temp;
                    temp = temp->right;
                    *(++temp_top) = temp;
                }
            }
            else {
                temp = node->right;
                *(++temp_top) = temp;
                temp_direction = TREE_RIGHT;
                while (temp->left) {
                    temp_prev = temp;
                    temp = temp->left;
                    *(++temp_top) = temp;
                }
            }

            *(++top) = temp; //the temp_top node is the one that replaces the deleted node
            top = temp_top;  //make top point to the top of the stack
        }
        //if the found node isn't the deleted nodes child, we need to "cut it apart" from where it was
        //we remove the found node, and connect its only child (there is no case where it has both)
        //to the found node's root
        if (temp != node->left && temp != node->right) {
            if (temp_direction == TREE_LEFT) {
                if (temp->left) {
                    temp_prev->right = temp->left;
                }
                else temp_prev->right = NULL;
            }
            else {
                if (temp->right) {
                    temp_prev->left = temp->right;
                }
                else temp_prev->left = NULL;
            }
            temp->left = NULL;
            temp->right = NULL;
        }

        //attach the replacement node (temp)
        if (!prev || direction == TREE_ROOT) {
            priv->root = temp;
        }
        else if (direction == TREE_LEFT) {
            prev->left = temp;
        }
        else {
            prev->right = temp;
        }

        //attach the replacement node to the rest of the tree
        if (!temp->right) temp->right = node->right;
        if (!temp->left) temp->left = node->left;

    }
    else {
        //if it has only one child
        if (node->left) temp = node->left;
        else temp = node->right;

        if (!prev || direction == TREE_ROOT) {
            priv->root = temp;
            priv->height = temp? temp->height:0;
        }
        else if (direction == TREE_LEFT) prev->left = temp;
        else prev->right = temp;

    }

    //todo: i think that this is the problem
    if (top >= stack) {
        while (top) {
            top = avl_balance(stack, top, priv);
        }
    }

    priv->height = priv->root? priv->root->height : 0;
    pthread_mutex_unlock(&(priv->mutex));

    free(stack);
    //todo: use user defined free for data
    free(node->data);
    free(node);

    return 0;
}

int avl_search(tree_t* t, void* data) {
    tree_node_t *node;
    tree_node_t *turn_node = NULL;
    int cmp_res;
    cmp_f cmp;

    if (!(t && data)) return -1;

    pthread_mutex_lock(&(t->priv->mutex));
    node = t->priv->root;
    cmp = t->priv->cmp;

    while (node != NULL) {
        cmp_res = cmp(data, node->data);

        if (cmp_res < 0) node = node->left;
        else {
            turn_node = node;
            node = node->right;
        }
    }
    if (!turn_node) {
        pthread_mutex_unlock(&(t->priv->mutex));
        return 1;
    }
    if (cmp(data, turn_node->data) == 0) {
        memcpy(data, turn_node->data, t->priv->data_size);
        pthread_mutex_unlock(&(t->priv->mutex));
        return 0;
    }
    pthread_mutex_unlock(&(t->priv->mutex));
    return 1;
}

int avl_search_pin(tree_t *t, void* data, void** ret_data) {
    tree_node_t *node;
    tree_node_t *turn_node = NULL;
    int cmp_res;
    cmp_f cmp;

    if (!t || !data || !ret_data) return -1;
    pthread_mutex_lock(&(t->priv->mutex));
    node = t->priv->root;
    cmp = t->priv->cmp;

    while (node != NULL) {
        cmp_res = cmp(data, node->data);

        if (cmp_res < 0) node = node->left;
        else {
            turn_node = node;
            node = node->right;
        }
    }
    if (turn_node) {
        if (cmp(data, turn_node->data) == 0) {
            *ret_data = turn_node->data;
            return 0;
        }
    }
    *ret_data = NULL;
    return 1;
}
int avl_search_release(tree_t *t) {
    if (!t) return -1;
    if (!t->priv) return -1;
    return pthread_mutex_unlock(&t->priv->mutex);
}

/*AVL HELPERS*/
FORCE_INLINE void rotate_left(tree_node_t *node, tree_node_t *root, tree_priv_t* tree) {
    tree_node_t *b;

    if (!node) return;
    if (!node->right) return;

    b = node->right;

    //node->right is the new root
    if (tree->root != node){
        if (!root) return;
        if (node == root->right) root->right = b;
        else root->left = b;
    }
    else {
        tree->root = b;
    }

    node->right = b->left;
    b->left = node;

    //update node's height and then b's height
    node->height = GET_HEIGHT(node);
    b->height = GET_HEIGHT(b);
}
FORCE_INLINE void rotate_right(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
    tree_node_t *b;

    if (!node) return;
    if (!node->left) return;

    b = node->left;

    //b is the new root
    if (tree->root != node){
        if (!root) return;
        if (node == root->right) root->right = b;
        else root->left = b;
    }
    else tree->root = b;

    node->left = b->right;
    b->right = node;

    //update the node's height and then b's height
    node->height = GET_HEIGHT(node);
    b->height = GET_HEIGHT(b);
}
FORCE_INLINE void rotate_left_right(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
    tree_node_t *a;
    tree_node_t *b;

    if (!node) return;

    //__left rotation on the left child__//
    a = node->left;
    b = a->right;

    //b is the new root of the subtree
    node->left = b;

    //change children
    a->right = b->left;
    b->left = a;

    //update heights: first a's then b's
    a->height = GET_HEIGHT(a);
    b->height = GET_HEIGHT(b);

    //__right rotation on the unbalanced node__//
    b = node->left;

    //b is the new root
    if (tree->root != node){
        if (root == NULL) return;
        if (node == root->right) root->right = b;
        else root->left = b;
    }

    else tree->root = b;


    node->left = b->right;
    b->right = node;

    //update the heights, first node's and then b's
    node->height = GET_HEIGHT(node);
    b->height = GET_HEIGHT(b);
}
FORCE_INLINE void rotate_right_left(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
    tree_node_t *a;
    tree_node_t *b;
    if (!node) return;

    //__right rotation on the right child__//
    a = node->right;
    b = a->left;

    //b is the new root of the subtree
    node->right = b;

    a->left = b->right;
    b->right = a;

    //update heights: first a's then b's
    a->height = GET_HEIGHT(a);
    b->height = GET_HEIGHT(b);

    //__left rotation on the unbalanced node__//
    b = node->right;

    //b is the new root
    if (tree->root != node) {
        if (root == NULL) return;
        if (node == root->right) root->right = b;
        else root->left = b;
    }
    else tree->root = b;


    node->right = b->left;
    b->left = node;

    //update the heights, first node's and then b's
    node->height = GET_HEIGHT(node);
    b->height = GET_HEIGHT(b);
}

tree_node_t** avl_balance(tree_node_t** stack, tree_node_t** top, tree_priv_t* tree) {
    tree_node_t *heavy_child;
    tree_node_t **node;
    tree_node_t **ret_node;

    if (!stack || !top || !tree) return NULL;
    if (!(tree->root)) return NULL;

    node = top;

    while (node >= stack) {
        //update-heights and calculate balance factors
        if ((*node)->right != NULL && (*node)->left != NULL) {
            (*node)->height = 1 + (
                (*node)->right->height > (*node)->left->height ? (*node)->right->height : (*node)->left->height
                );
            (*node)->bf = (int32_t)((int64_t)(*node)->right->height - (int64_t)(*node)->left->height);
        }
        else if ((*node)->right == NULL && (*node)->left != NULL) {
            (*node)->height = (*node)->left->height + 1;
            (*node)->bf = (int32_t)(-((int64_t)(*node)->left->height));
        }
        else if ((*node)->right != NULL && (*node)->left == NULL) {
            (*node)->height = (*node)->right->height + 1;
            (*node)->bf = (int32_t)((*node)->right->height);
        }
        else {
            (*node)->height = 1;
            (*node)->bf = 0;
        }

        if (abs((int)((*node)->bf)) > 1) //the first node we find unbalanced
            break;

        --node; //go down the stack
    }

    if (node < stack) return NULL; //if the node is not in the stack then the tree is already balanced

    //find the heavy child of the unbalanced node
    if ((*node)->right != NULL && (*node)->left != NULL) {
        heavy_child = (*node)->right->height > (*node)->left->height ? (*node)->right : (*node)->left;
    }
    else if ((*node)->right == NULL) {
        heavy_child = (*node)->left;
    }
    else {
        heavy_child = (*node)->right;
    }

    if (heavy_child == (*node)->right) {
        //clang says heavy child can be null, this can not happen
        if (heavy_child->bf >= 0) {
            //right-right
            rotate_left(*node, (node  > stack)?*(node - 1):NULL, tree);
        }
        else {
            //right-left
            rotate_right_left(*node, (node  > stack)?*(node - 1):NULL, tree);
        }
    }
    else {
        if (heavy_child->bf <= 0) {
            //left-left
            rotate_right(*node, (node  > stack)?*(node - 1):NULL, tree);
        }
        else {
            //left-right
            rotate_left_right(*node, (node  > stack)?*(node - 1):NULL, tree);
        }
    }
    //node has its height updated already in the rotation functions
    //so we need to update from its root and up
    ret_node = --node;
    while (node >= stack){
        (*node)->height = GET_HEIGHT(*node);
        --node;
    }

    if (tree->root) tree->height = tree->root->height;
    else tree->height = 0;

    if (ret_node < stack) return NULL;
    return ret_node;
}



void print_root(tree_t *tree) {
    if (!tree) return;
    printf("root:%llu\n", *(uint64_t *)tree->priv->root->data);
}
size_t tree_height(tree_t *tree) {
    if (!tree) return 0;
    return tree->priv->height;
}

void print_child_heights(tree_t *tree) {
    if (!tree) return;
    printf("\n%d ", tree->priv->root->right->height);
    printf("%d\n", tree->priv->root->left->height);
}

void print_tree(tree_t *tree) {
    if (!tree) return;
    tree_node_t **stack_1 = malloc(sizeof(tree_node_t *) * (1<<(tree->priv->height-1)));
    tree_node_t **stack_2 = malloc(sizeof(tree_node_t *) * (1<<(tree->priv->height-1)));
    if (!stack_1 || !stack_2) {
        free(stack_1);
        free(stack_2);
        return;
    }
    tree_node_t **top_1 = stack_1 - 1;
    tree_node_t **top_2 = stack_2 - 1;
    tree_node_t **stack;
    tree_node_t **top;
    tree_node_t *node;
    uint64_t non_null = 0;

    FILE *fd = fopen("tree.txt", "w");
    if (fd == NULL) {
        free(stack_1);
        free(stack_2);
        return;
    }

    *(++top_1) = tree->priv->root;
    if (tree->priv->root) non_null = 1;

    while (non_null) {
        non_null = 0;
        while (top_1 >= stack_1) {
            node = *top_1;
            top_1--;
            if (node) {
                printf(" %llu ", *(uint64_t *)(node->data));
                fprintf(fd, " %llu ", *(uint64_t *)(node->data));
                *(++top_2) = node->right;
                if (node->right) non_null++;
                *(++top_2) = node->left;
                if (node->left) non_null++;
            }
            else {
                printf(" null ");
                fprintf(fd, " null ");
            }

        }
        stack = stack_1;
        stack_1 = stack_2;
        stack_2 = stack;
        top = top_1;
        top_1 = top_2;
        top_2 = top;
        printf("\n\n");
        fprintf(fd, "\n\n");
    }

    free(stack_1);
    free(stack_2);
    fclose(fd);
}