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


#ifndef QUEUE_H
#define QUEUE_H

#define QUEUE_MAX_SIZE 1000
#include <pthread.h>
#include <stdint.h>

#include "indigo_types.h"

typedef enum QUEUE_EVENT_TYPE {
     QET_TERMINATION = 0,
     QET_ERROR,
     QET_INTERFACE_UPDATE,
     QET_PACKET_BURST,
     QET_NEW_PACKET,
     QET_SIGNATURE_REQUEST,
     QET_SIGNATURE_RESPONSE,
     QET_FILE_SENDING_REQUEST,
     QET_FILE_SENDING_RESPONSE,
     QET_SESSION_START,
     QET_SESSION_REJECTED,
     QET_SEND_FILE,
     QET_EXPECT_SEND_RESPONSE,
     QET_RESEND_FILE_CHUNK,
}QUEUE_EVENT_TYPE, QET;

/*BELLOW ARE THE EXPECTED DATA FORMAT OF THE RESPECTIVE EVENT TYPES*/

typedef struct Q_NEW_PACKET_DATA {
    packet_t *packet;
}Q_NEW_PACKET_DATA;

typedef struct Q_FILE_SENDING_REQUEST {
    uint64_t serial;
    size_t file_size; //the size of the file in bytes
    wchar_t file_name[MAX_PATH];
    uint32_t addr;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    char zero[4];
}Q_FILE_SENDING_REQUEST, Q_SESSION_START;

typedef session_id_t Q_SESSION_REJECTED, Q_EXPECT_SEND_RESPONSE ;

typedef active_file_t Q_SEND_FILE;

typedef struct Q_RESEND_FILE_CHUNK {
    transmission_control_data_t *control;
    session_id_t session_id;
}Q_RESEND_FILE_CHUNK;



typedef enum queue_options {
    QOPT_BLOCK = 0,
    QOPT_NON_BLOCK = 1,
}QOPT;

/*Implementation of a queue data structure.
 *the queue is implemented with a linked list and access to the queue should only be given with the given functions.
 *every node holds a pointer, to the data of the node, and the size of that data
 */
typedef struct QNODE {
    struct QNODE *next;
    void *data;
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
uint8_t queue_push(QUEUE *queue, void * data, QET type);
QNODE *queue_pop(QUEUE *queue, QOPT option);
QNODE *queue_peek(QUEUE *queue);
void queue_remove_front(QUEUE *queue);

//get the number of nodes in the Queue
size_t get_queue_size(QUEUE *queue);
uint8_t queue_is_empty(QUEUE *queue);


#endif //QUEUE_H