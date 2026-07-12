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

#include "Queue.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <log.h>

// todo: use mempool for the queue
//
// general purpose queue
//

size_t get_queue_size(QUEUE *queue)
{
    if (queue == NULL)
        return 0;

    size_t size;

    pthread_mutex_lock(&queue->mutex);
    size = queue->qsize;
    pthread_mutex_unlock(&queue->mutex);

    return size;
}

// call this only once when the queue is created, else there will be a memory leak
uint8_t init_queue(QUEUE *queue)
{
    if (queue == NULL) {
        log_warn("queue is null | return 1");
        return 1;
    }

    queue->firstNode = NULL;
    queue->lastNode = NULL;
    queue->qsize = 0;

    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        log_error("pthread_mutex_init() failed for queue mutex | return 1 | errno %d", errno);
        return 1;
    }
    if (pthread_cond_init(&queue->cond, NULL) != 0) {
        log_error("pthread_cond_init() failed for queue condition | return 1 | errno %d", errno);
        return 1;
    }
    return 0;
}

uint8_t queue_is_empty(QUEUE *queue)
{
    uint8_t isEmpty;
    if (queue == NULL) {
        log_warn("queue is null | return 1");
        return 1;
    }

    pthread_mutex_lock(&queue->mutex);

    isEmpty = (queue->qsize == 0);

    pthread_mutex_unlock(&queue->mutex);

    return isEmpty;
}

// first destroy the threads and then destroy the queue
void destroy_queue(QUEUE *queue)
{
    if (queue == NULL)
        return;

    pthread_mutex_lock(&queue->mutex);

    QNODE *prev = NULL;
    QNODE *curr = queue->firstNode;
    while (curr != NULL) {
        prev = curr;
        curr = curr->next;
        free(prev->data);
        free(prev);
    }

    queue->firstNode = NULL;
    queue->lastNode = NULL;
    queue->qsize = 0;

    pthread_mutex_unlock(&queue->mutex);

    if (pthread_mutex_destroy(&queue->mutex) != 0) {
        log_error("pthread_mutex_destroy() failed | errno %d", errno);
    }
    if (pthread_cond_destroy(&queue->cond) != 0) {
        log_error("pthread_cond_destroy() failed | errno %d", errno);
    }
}

QNODE *create_qnode()
{
    QNODE *node = calloc(1, sizeof(QNODE));
    if (node == NULL) {
        log_error("calloc() failed allocating %d bytes for queue node | return NULL", sizeof(QNODE));
        return NULL;
    }
    return node;
}

void destroy_qnode(QNODE *node)
{
    if (node == NULL) {
        log_warn("node is null | return 1");
        return;
    }
    free(node);
}

FORCE_INLINE void queue_lock(QUEUE *queue) { pthread_mutex_lock(&(queue->mutex)); }
FORCE_INLINE void queue_unlock(QUEUE *queue) { pthread_mutex_unlock(&(queue->mutex)); }

uint8_t queue_push_tu(QUEUE *queue, void *const data, QET type)
{
    QNODE *temp = NULL;

    if (queue == NULL)
        return 1;

    temp = create_qnode();
    if (temp == NULL) {
        log_error("create_qnode() failed | return 1");
        return 1;
    }

    temp->data = data;
    temp->type = type;
    temp->next = NULL;

    if (queue->firstNode != NULL) {
        queue->lastNode->next = temp;
        queue->lastNode = temp;
    }
    else {
        queue->firstNode = temp;
        queue->lastNode = temp;
    }

    queue->qsize++;
    pthread_cond_signal(&queue->cond);

    return 0;
}

QNODE *queue_pop_tu(QUEUE *queue, QOPT option)
{
    QNODE *temp = NULL;

    if (queue == NULL)
        return NULL;

    // block until there is a new node
    while ((queue->firstNode == NULL) && (option == QOPT_BLOCK)) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    if (queue->firstNode == NULL) {
        return NULL;
    }

    temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;
    if (queue->firstNode == NULL) {
        queue->lastNode = NULL;
    }
    queue->qsize--;

    temp->next = NULL;

    return temp;
}

QNODE *queue_peek_tu(QUEUE *queue)
{
    QNODE *temp = NULL;
    QNODE *ret_node = NULL;

    if (queue == NULL) {
        return NULL;
    }

    if (queue->firstNode == NULL) {
        return NULL;
    }

    temp = queue->firstNode;

    ret_node = create_qnode();
    if (ret_node == NULL) {
        log_error("create_qnode() failed | return NULL");
        return NULL;
    }
    memcpy(ret_node, temp, sizeof(QNODE));

    return ret_node;
}

void queue_remove_front_tu(QUEUE *queue)
{
    if (queue == NULL) {
        return;
    }
    if (queue->firstNode == NULL) {
        return;
    }

    QNODE *temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;

    if (queue->firstNode == NULL) {
        queue->lastNode = NULL;
    }
    queue->qsize--;

    free(temp->data);
    free(temp);
}

uint8_t queue_push(QUEUE *queue, void *const data, QET type)
{
    QNODE *temp = NULL;

    if (queue == NULL)
        return 1;

    pthread_mutex_lock(&queue->mutex);

    temp = create_qnode();
    if (temp == NULL) {
        log_error("create_qnode() failed");
        pthread_mutex_unlock(&queue->mutex);
        return 1;
    }

    temp->data = data;
    temp->type = type;
    temp->next = NULL;

    if (queue->firstNode != NULL) {
        queue->lastNode->next = temp;
        queue->lastNode = temp;
    }
    else {
        queue->firstNode = temp;
        queue->lastNode = temp;
    }

    queue->qsize++;
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);

    return 0;
}

QNODE *queue_pop(QUEUE *queue, QOPT option)
{
    QNODE *temp = NULL;

    if (queue == NULL)
        return NULL;

    pthread_mutex_lock(&queue->mutex);

    // block until there is a new node
    while ((queue->firstNode == NULL) && (option == QOPT_BLOCK)) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }

    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;
    if (queue->firstNode == NULL) {
        queue->lastNode = NULL;
    }
    queue->qsize--;

    temp->next = NULL;

    pthread_mutex_unlock(&queue->mutex);

    return temp;
}

QNODE *queue_peek(QUEUE *queue)
{
    QNODE *temp = NULL;
    QNODE *ret_node = NULL;

    if (queue == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&queue->mutex);

    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }

    temp = queue->firstNode;

    ret_node = create_qnode();
    if (ret_node == NULL) {
        log_error("create_qnode() failed");
        return NULL;
    }
    memcpy(ret_node, temp, sizeof(QNODE));

    pthread_mutex_unlock(&queue->mutex);
    return ret_node;
}

void queue_remove_front(QUEUE *queue)
{
    if (queue == NULL) {
        return;
    }
    pthread_mutex_lock(&queue->mutex);
    if (queue->firstNode == NULL) {
        pthread_mutex_unlock(&queue->mutex);
        return;
    }

    QNODE *temp = queue->firstNode;

    queue->firstNode = queue->firstNode->next;

    if (queue->firstNode == NULL) {
        queue->lastNode = NULL;
    }
    queue->qsize--;

    free(temp->data);
    free(temp);

    pthread_mutex_unlock(&queue->mutex);
}
