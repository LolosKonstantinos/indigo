//
// Created by Constantin on 15/10/2025.
//
#include "binary_tree.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TREE_RIGHT (1)
#define TREE_ROOT (0)
#define TREE_LEFT (-1)

#define GET_HEIGHT(node) \
((node)->right?\
    ( (node)->left?\
        (1 + (((node)->right->height > (node)->left->height)?(node)->right->height:(node)->left->height)):\
((node)->right->height+1) ):\
    ( (node)->left?((node)->left->height+1):0 ))


struct tree_priv_t {
    pthread_mutex_t mutex;
    tree_node_t *root;
    size_t data_size;
    cmp_f cmp;          // the function based on which we do struct comparison
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
    char bf;                    //kinda useless
    char zero[3];
};


int new_tree(tree_t **t, const cmp_f cmp, const size_t data_size, const char type) {
    tree_t *temp;
    tree_priv_t *priv;

    if (!*t || !cmp || !data_size) {
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
    pthread_mutex_init(&priv->mutex, NULL);

    temp->priv = priv;
    if (type == BINARY_TREE_TYPE_AVL) {
        temp->search = avl_search;
        temp->remove = avl_delete;
        temp->insert = avl_insert_copy;
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
    if(node == NULL) {
        return NULL;
    }
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

    node = new_node();
    if (!node) {
        pthread_mutex_unlock(&(priv->mutex));
        return 1;
    }
    node->data = malloc(priv->data_size);
    if (!node->data) {
        pthread_mutex_unlock(&(priv->mutex));
        free(node);
        return 1;
    }
    memcpy(node->data, data, priv->data_size);

    stack = malloc(sizeof(tree_node_t *) * (priv->height + 2));
    if (!stack) {
        pthread_mutex_unlock(&(priv->mutex));
        free(node->data);
        free(node);
        return 1;
    }
    top = stack - 1;

    if (!priv->root) {
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
            free(node->data);
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

    avl_balance(stack, top, priv);

    pthread_mutex_unlock(&(priv->mutex));
    free(stack);
    return 0;
}

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

    if (!t || !data) return -1;
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
        //add to the stack
        *(++top) = node;

        cmp_res = cmp(data, node->data);
        if (cmp_res == 0) break;

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
    if (!node) {
        pthread_mutex_unlock(&(priv->mutex));
        free(stack);
        return 1;
    }
    --top; //the top node is the one to be deleted

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
            tree_node_t**temp_top;
            tree_node_t** temp_stack = malloc(sizeof(tree_node_t*) * (priv->height - node->height + 1));
            if (!temp_stack) {
                pthread_mutex_unlock(&(priv->mutex));
                free(stack);
                return -1;
            }
            temp_top = temp_stack - 1;

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
            temp_top = temp_stack;
            while (*temp_top != temp) {
                *(++top) = *temp_top;
                ++temp_top;
            }

            free(temp_stack);
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
        else if (direction == TREE_LEFT) {
            prev->left = temp;
        }
        else{
            prev->right = temp;
        }

    }

    if (top >= stack) {
        while (top)
            top = avl_balance(stack, top, priv);
    }

    pthread_mutex_unlock(&(priv->mutex));

    free(stack);
    free(node->data);
    free(node);
    return 0;
}

//todo: if we need to modify the data then we should have an unsafe function that needs the mutex locked before a call
int avl_search(tree_t* t, void* data) {
    tree_node_t *node;
    tree_node_t *turn_node = NULL;
    int cmp_res;
    cmp_f cmp;

    if (!t || !data) return -1;
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
inline void rotate_left(tree_node_t *node, tree_node_t *root, tree_priv_t* tree) {
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
inline void rotate_right(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
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
inline void rotate_left_right(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
    tree_node_t *a;
    tree_node_t *b;

    if (!node) return;

    //__rotate left the left child__//
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

    //__rotate right__//
    b = node->left;

    //node->left is the new root
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
inline void rotate_right_left(tree_node_t *node, tree_node_t* root, tree_priv_t* tree) {
    tree_node_t *a;
    tree_node_t *b;
    if (!node) return;

    //__rotate right the right child__//
    a = node->right;
    b = a->left;

    //b is the new root of the subtree
    node->right = b;

    a->left = b->right;
    b->right = a;

    //update heights: first a's then b's
    a->height = GET_HEIGHT(a);
    b->height = GET_HEIGHT(b);

    //__rotate left__//
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
        if ((*node)->right == NULL && (*node)->left == NULL) {
            (*node)->height = 0;
            (*node)->bf = 0;
        }
        else if ((*node)->right == NULL && (*node)->left != NULL) {
            (*node)->height = (*node)->left->height + 1;
            (*node)->bf = (char)(-((*node)->left->height));
        }
        else if ((*node)->right != NULL && (*node)->left == NULL) {
            (*node)->height = (*node)->right->height + 1;
            (*node)->bf = (char)((*node)->right->height);
        }
        else {
            (*node)->height = 1 + ((*node)->right->height > (*node)->left->height ? (*node)->right->height : (*node)->left->height);
            (*node)->bf = (char)((int64_t)(*node)->right->height - (int64_t)(*node)->left->height);
        }

        if (abs((int)((*node)->bf)) > 1) //the first node we find unbalanced
            break;

        --node; //go down the stack
    }

    if (node < stack) return NULL; //if the node is not in the stack then the tree is already balanced

    //find the heavy child
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
        //todo: heavy child may be null????
        if (heavy_child->bf >= 0) {
            //right-right
            rotate_left(*node, (node  > stack)?*(node -1):NULL, tree);
        }
        else {
            //right-left
            rotate_right_left(*node, (node  > stack)?*(node -1):NULL, tree);
        }
    }
    else {
        if (heavy_child->bf <= 0) {
            //left-left
            rotate_right(*node, (node  > stack)?*(node -1):NULL, tree);
        }
        else {
            //left-right
            rotate_left_right(*node, (node  > stack)?*(node -1):NULL, tree);
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