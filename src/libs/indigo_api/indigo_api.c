/*
Copyright (c) 2026 Lolos Konstantinos

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

#include <pthread.h>
#include <stdatomic.h>
#include <event_flags.h>
#include <queue.h>
#include "indigo_api.h"
#include "indigo_private_api.h"

#include "config.h"

#define DEFAULT_BUFFER_SIZE 16

// static variables used for safe api initialization
static QUEUE *_Atomic tmp_manager_queue;
static QUEUE *_Atomic tmp_send_queue;
static QUEUE *_Atomic tmp_packet_handler_queue;
static EFLAG *_Atomic tmp_send_flag;
static tree_t *_Atomic tmp_known_keys;

static pthread_once_t init_control = PTHREAD_ONCE_INIT;
static atomic_char is_initialized = 0;
static atomic_char initialization_error = 0;

typedef struct {
    QUEUE *manager_queue;
    QUEUE *send_queue;
    QUEUE *packet_handler_queue;
    EFLAG *send_flag;
    tree_t *known_keys;

    indigo_remote_device_t *remote_devices;
    _Atomic size_t remote_device_count;
    indigo_client_session_t *client_sessions;
    _Atomic size_t client_session_count;
    indigo_server_session_t *server_sessions;
    _Atomic size_t server_session_count;

    atomic_char new_device_data;
    atomic_char new_client_session_data;
    atomic_char new_server_session_data;
    char zero[5];

    pthread_mutex_t mutex;
} ui_api_data_t;

static ui_api_data_t *ui_api_data;

static void init(void)
{
    void *tmp;

    tmp = malloc(sizeof(ui_api_data_t));
    if (!tmp) {
        atomic_store(&initialization_error, 1);
        return;
    }
    ui_api_data = tmp;

    ui_api_data->manager_queue = atomic_load(&tmp_manager_queue);
    ui_api_data->send_queue = atomic_load(&tmp_send_queue);
    ui_api_data->packet_handler_queue = atomic_load(&tmp_packet_handler_queue);
    ui_api_data->send_flag = atomic_load(&tmp_send_flag);
    ui_api_data->known_keys = atomic_load(&tmp_known_keys);

    ui_api_data->remote_devices = NULL;
    atomic_store(&ui_api_data->remote_device_count, 0);
    ui_api_data->client_sessions = NULL;
    atomic_store(&ui_api_data->client_session_count, 0);
    ui_api_data->server_sessions = NULL;
    atomic_store(&ui_api_data->server_session_count, 0);

    atomic_store(&ui_api_data->new_device_data, 0);
    atomic_store(&ui_api_data->new_client_session_data, 0);
    atomic_store(&ui_api_data->new_server_session_data, 0);

    if (pthread_mutex_init(&ui_api_data->mutex, NULL)) {
        atomic_store(&initialization_error, 1);
    }

    atomic_store(&is_initialized, 1);
}

int ui_api_init(QUEUE *manager_queue, QUEUE *send_queue, QUEUE *packet_handler_queue, EFLAG *send_flag,
                tree_t *known_keys)
{

    atomic_store(&tmp_manager_queue, manager_queue);
    atomic_store(&tmp_send_queue, send_queue);
    atomic_store(&tmp_packet_handler_queue, packet_handler_queue);
    atomic_store(&tmp_send_flag, send_flag);
    atomic_store(&tmp_known_keys, known_keys);

    pthread_once(&init_control, init);

    if (atomic_load(&initialization_error))
        return 1;

    return 0;
}

int ui_error() { return atomic_load(&initialization_error); }

int get_device_info(void **device_array, size_t *device_array_size)
{
    void *restrict tmp;
    size_t size = atomic_load(&ui_api_data->remote_device_count);
    char one = 1;

    if (!device_array)
        return 1;

    pthread_mutex_lock(&ui_api_data->mutex);
    if (size <= 0) {
        *device_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return 0;
    }

    // allocate a new array
    tmp = malloc(size * sizeof(indigo_remote_device_t));
    if (!tmp) {
        *device_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return -1;
    }

    // copy the device data inside the new array
    memcpy(tmp, ui_api_data->remote_devices, size * sizeof(indigo_remote_device_t));

    // return the copied data
    *device_array = tmp;

    if (device_array_size)
        *device_array_size = size;

    atomic_compare_exchange_strong(&ui_api_data->new_device_data, &one, 0);

    pthread_mutex_unlock(&ui_api_data->mutex);

    return 0;
}

int get_client_session_info(void **client_session_array, size_t *client_session_array_size)
{
    void *restrict tmp;
    size_t size = atomic_load(&ui_api_data->client_session_count);
    char one = 1;

    if (!client_session_array)
        return 1;

    pthread_mutex_lock(&ui_api_data->mutex);
    if (size <= 0) {
        *client_session_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return 0;
    }

    // allocate a new array
    tmp = malloc(size * sizeof(indigo_client_session_t));
    if (!tmp) {
        *client_session_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return -1;
    }

    // copy the session data inside the new array
    memcpy(tmp, ui_api_data->client_sessions, size * sizeof(indigo_client_session_t));

    // return the copied data
    *client_session_array = tmp;

    if (client_session_array_size)
        *client_session_array_size = size;

    atomic_compare_exchange_strong(&ui_api_data->new_client_session_data, &one, 0);

    pthread_mutex_unlock(&ui_api_data->mutex);

    return 0;
}

int get_server_session_info(void **server_session_array, size_t *server_session_array_size)
{
    void *restrict tmp;
    size_t size = atomic_load(&ui_api_data->server_session_count);
    char one = 1;

    if (!server_session_array)
        return 1;

    pthread_mutex_lock(&ui_api_data->mutex);
    if (size <= 0) {
        *server_session_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return 0;
    }

    // allocate a new array
    tmp = malloc(size * sizeof(indigo_server_session_t));
    if (!tmp) {
        *server_session_array = NULL;
        pthread_mutex_unlock(&ui_api_data->mutex);
        return -1;
    }

    // copy the session data inside the new array
    memcpy(tmp, ui_api_data->server_sessions, size * sizeof(indigo_server_session_t));

    // return the copied data
    *server_session_array = tmp;

    if (server_session_array_size)
        *server_session_array_size = size;

    atomic_compare_exchange_strong(&ui_api_data->new_server_session_data, &one, 0);

    pthread_mutex_unlock(&ui_api_data->mutex);

    return 0;
}

size_t get_device_count() { return atomic_load(&ui_api_data->remote_device_count); }

size_t get_client_session_count() { return atomic_load(&ui_api_data->client_session_count); }

size_t get_server_session_count() { return atomic_load(&ui_api_data->server_session_count); }

int broadcast_init_packet() { return set_event_flag(ui_api_data->send_flag, EF_SEND_INIT_PACKET); }

int register_file_to_send(char *file_path, unsigned char id[crypto_sign_PUBLICKEYBYTES])
{
    Q_SEND_FILE *send_file_queue_node;
    int ret;
    if (!file_path || !id) return -1;

    send_file_queue_node = malloc(sizeof(Q_SEND_FILE));
    if (!send_file_queue_node) return -1;

    send_file_queue_node->filename = file_path;
    mempcpy(send_file_queue_node->id, id, crypto_sign_PUBLICKEYBYTES);

    ret = queue_push(ui_api_data->send_queue, send_file_queue_node, QET_SEND_FILE);
    if (ret) {
        free(send_file_queue_node);
        return -1;
    }

    return 0;
}

int register_remote_device_status(unsigned char id[crypto_sign_PUBLICKEYBYTES], uint64_t status)
{
    if (!id) return -1;

    //check if the status is a valid value
    switch (status) {
        case KNOWN_KEY_STATUS_TOO_GOOD:
        case KNOWN_KEY_STATUS_GOOD:
        case KNOWN_KEY_STATUS_BAD:
        case KNOWN_KEY_STATUS_EVIL_AND_SINISTER:
            break;
        default: return -1;
    }

    if (edit_known_key(ui_api_data->known_keys,id,status)) return -1;

    return 0;
}
