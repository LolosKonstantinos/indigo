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

#ifndef INDIGO_UI_API_H
#define INDIGO_UI_API_H

#include "binary_tree.h"

#include <event_flags.h>
#include <queue.h>
#include <pthread.h>
#include <stdint.h>
#include <sodium/crypto_sign.h>

#define MAX_USERNAME_LEN 32

typedef struct {
    uint64_t status;
    struct timespec timestamp; // the last time the device was seen
    int port;
    uint32_t ip;
    unsigned char peer_pk[crypto_sign_PUBLICKEYBYTES];
    char username[MAX_USERNAME_LEN * sizeof(uint32_t)];
} indigo_remote_device_t;

typedef struct {
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    uint64_t session_serial;
    size_t file_size;
    size_t bytes_sent;
    struct timespec start_time_realtime;
    struct timespec start_time_monotonic;
    struct timespec end_time_monotonic;
    uint32_t ip;
    char is_completed;
    unsigned char zero[3];
} indigo_client_session_t;

typedef struct {
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    uint64_t session_serial;
    struct timespec timestamp;
    struct timespec start_time_realtime;
    struct timespec start_time_monotonic;
    struct timespec end_time_monotonic;
    uint64_t total_packet_count;
    uint64_t packets_writen;
    size_t bytes_moved;
    uint32_t ip;
    unsigned char zero[4];
} indigo_server_session_t;

int ui_api_init(QUEUE *manager_queue, QUEUE *send_queue, QUEUE *packet_handler_queue, EFLAG *send_flag,
                tree_t *known_keys);
int ui_error();

int get_device_info(void **device_array, size_t *device_array_size);
int get_client_session_info(void **client_session_array, size_t *client_session_array_size);
int get_server_session_info(void **server_session_array, size_t *server_session_array_size);
size_t get_device_count();
size_t get_client_session_count();
size_t get_server_session_count();

int register_file_to_send(char *file_path, unsigned char id[crypto_sign_PUBLICKEYBYTES]);
int register_remote_device_status(unsigned char id[crypto_sign_PUBLICKEYBYTES], uint64_t status);
int broadcast_init_packet();
int terminate_indigo();
int send_packet(void *data, size_t data_size);

#endif // INDIGO_UI_API_H
