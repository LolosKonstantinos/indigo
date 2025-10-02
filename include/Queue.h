//
// Created by Κωνσταντίνος on 7/8/2025.
//


#ifndef QUEUE_H
#define QUEUE_H

#define QUEUE_MAX_SIZE 1000
#include <pthread.h>
#include <stdint.h>

typedef enum   QUEUE_EVENT_TYPE {
 QET_TERMINATION = 0,
 QET_ERROR = 1,
 QET_INTERFACE_UPDATE = 2,
 QET_PACKET_BURST = 3,
 QET_NEW_PACKET = 4,
 QET_SIGNATURE_REQUEST = 5,
 QET_SIGNATURE_RESPONSE = 6,
}QUEUE_EVENT_TYPE, QET;

typedef enum queue_options {
 QOPT_BLOCK = 0,
 QOPT_NON_BLOCK = 1,
}QOPT;

/*Implementation of a queue data structure.
 *the queue is implemented with a linked list and access to the queue should only be given with the given functions.
 *every node holds a pointer, to the element of the node, and the size of that element
 *even though it is harder to use as the queue doesn't store a specific data type, it can be more versatile
 */
typedef struct QNODE {
 struct QNODE *next;
 void *buf; //if the buffer contains a pointer to another buffer or other heap data ==> MEMORY LEAK!
 size_t size;//size of the buffer
 QET type;
} QNODE;

typedef struct QUEUE {
 pthread_mutex_t mutex;
 pthread_cond_t cond;
 QNODE *firstNode;
 QNODE *lastNode;
 size_t qsize;//number of nodes
} QUEUE;


//open a Queue and free it
uint8_t init_queue(QUEUE *queue);
void destroy_queue(QUEUE *queue);

//helper function to enqueue elements
QNODE *create_qnode();
void destroy_qnode(QNODE *node);

//add and get from the queue
uint8_t queue_push(QUEUE *queue, const void *data, size_t size, QET type);
QNODE *queue_pop(QUEUE *queue, QOPT option);
QNODE *queue_peek(QUEUE *queue);
void queue_remove_front(QUEUE *queue);

//get the number of nodes in the Queue
size_t get_queue_size(QUEUE *queue);
uint8_t queue_is_empty(QUEUE *queue);


#endif //QUEUE_H