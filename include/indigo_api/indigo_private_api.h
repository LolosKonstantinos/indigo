#ifndef INDIGO_INDIGO_PRIVATE_API_H
#define INDIGO_INDIGO_PRIVATE_API_H

#include "binary_tree.h"
#include <event_flags.h>
#include <queue.h>

//Initialize the indigo API.
// This function should be called before any thread tried to interact with the API.
// Subsequent calls to this function do not have any effect.
int ui_api_init(QUEUE *manager_queue, QUEUE *send_queue, QUEUE *packet_handler_queue, EFLAG *send_flag,
                tree_t *known_keys);

#endif // INDIGO_INDIGO_PRIVATE_API_H
