//
// Created by Κωνσταντίνος on 7/8/2025.
//

#include "Queue.h"

#include <stdlib.h>
#include <string.h>


//
//general purpose queue
//

size_t get_queue_size(QUEUE *queue) {
    if (queue == NULL) return 0;

    size_t size;

    pthread_mutex_lock(&queue->mutex);
    size = queue->qsize;
    pthread_mutex_unlock(&queue->mutex);

    return size;
}

//call this only once when the queue is created, else there will be a memory leak
uint8_t init_queue(QUEUE *queue) {
    if (queue == NULL) return 1;

    queue->firstNode = NULL;
    queue->lastNode = NULL;
    queue->qsize = 0;


    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        perror("pthread_mutex_init");
        return 1;
    }
    if (pthread_cond_init(&queue->cond, NULL) != 0) {
        perror("pthread_cond_init");
        return 1;
    }
    return 0;
}

uint8_t queue_is_empty(QUEUE *queue) {
    if (queue == NULL) return 1;

    pthread_mutex_lock(&queue->mutex);

    uint8_t isEmpty = (queue->qsize == 0);

    pthread_mutex_unlock(&queue->mutex);

    return isEmpty;
}

//first destroy the threads and then destroy the queue
void destroy_queue(QUEUE *queue) {
    if (queue == NULL) return;

    pthread_mutex_lock(&queue->mutex);

    QNODE *prev = NULL;
    QNODE *curr = queue->firstNode;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        free(prev->buf);
        free(prev);
    }

    queue->firstNode = NULL;
    queue->lastNode = NULL;
    queue->qsize = 0;

    pthread_mutex_unlock(&queue->mutex);

    if (pthread_mutex_destroy(&queue->mutex) != 0) {
        perror("pthread_mutex_destroy");
    }
    if (pthread_cond_destroy(&queue->cond) != 0) {
        perror("pthread_cond_destroy");
    }
}

QNODE *create_qnode() {
    QNODE *node = (QNODE *)calloc(1,sizeof(QNODE));
    if (node == NULL) {
        perror("error allocating memory for queue node");
        return NULL;
    }
    return node;
}

void destroy_qnode(QNODE *node) {
    if (node == NULL) return;
    free(node->buf);
    free(node);
}

uint8_t queue_push(QUEUE *queue, const void *data, size_t size, QET type) {
    QNODE *temp = NULL;

    if (queue == NULL) return 1;

    pthread_mutex_lock(&queue->mutex);

    temp = create_qnode();
    if (temp == NULL) {
        perror("error allocating memory for queue node");
        pthread_mutex_unlock(&queue->mutex);
        return 1;
    }

    if (data != NULL) {
        temp->buf = malloc(size);
        if (temp->buf == NULL) {
            perror("error allocating memory for queue node");
            pthread_mutex_unlock(&queue->mutex);
            destroy_qnode(temp);
            return 1;
        }
        memcpy(temp->buf, data, size);
        temp->size = size;
    }
    else {
        temp->buf = NULL;
        temp->size = 0;
    }
        temp->type = type;
        temp->next = NULL;


    if (queue->firstNode == NULL) {
        queue->firstNode = temp;
        queue->lastNode = temp;
    }
    else {
        queue->lastNode->next = temp;
        queue->lastNode = temp;
    }
    queue->qsize++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

QNODE *queue_pop(QUEUE *queue, QOPT option) {
    QNODE *temp = NULL;

    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->mutex);



    //block until there is a new node
    while ((queue->firstNode == NULL) && (option == QOPT_BLOCK)) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;
    if (queue->firstNode == NULL) queue->lastNode = NULL;
    queue->qsize--;

    temp->next = NULL;

    pthread_mutex_unlock(&queue->mutex);

    return temp;
}

QNODE *queue_peek(QUEUE *queue) {
    QNODE *temp = NULL, *ret_node = NULL;

    if (queue == NULL) return NULL;

    pthread_mutex_lock(&queue->mutex);

    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    temp = queue->firstNode;


    ret_node = create_qnode();
    if (ret_node == NULL) {
        perror("error allocating memory for queue node");
        return NULL;
    }
    memcpy(ret_node, temp, sizeof(QNODE));

    ret_node->buf = malloc(temp->size);
    if (ret_node->buf == NULL) {
        perror("error allocating memory for queue node");
        pthread_mutex_unlock(&queue->mutex);
        destroy_qnode(ret_node);
        return NULL;
    }
    memcpy(ret_node->buf, temp->buf, temp->size);
    pthread_mutex_unlock(&queue->mutex);
    return ret_node;
}

void queue_remove_front(QUEUE *queue) {
    if (queue == NULL) return;
    pthread_mutex_lock(&queue->mutex);
    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return;
    }

    QNODE *temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;

    if (queue->firstNode == NULL) queue->lastNode = NULL;
    queue->qsize--;

    free(temp->buf);
    free(temp);

    pthread_mutex_unlock(&queue->mutex);
}