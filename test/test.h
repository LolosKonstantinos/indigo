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

#ifndef INDIGO_TEST_H
#define INDIGO_TEST_H

#include <stdint.h>

#define TEST_PASSED 1
#define TEST_FAILED 0

typedef int (* test)(void);

typedef struct test_t {
    test test;
    char name[64];
}test_t;

void run_tests(test_t *tests, uint64_t count);

//test utilities
int test_binary_tree();
int test_buffer();
int test_config();
int test_crypto();
int test_event_flags();
int test_mempool();
int test_queue();

//test core

//test net_io
int test_send_discovery_packets();
int test_register_single_receiver();
int test_send_packet();
int test_send_file_packet();
int test_send_next_file_packet();
int test_build_packet();
int test_send_info();
int test_recv_info();
int test_handle_array_from_send_info();
int test_handle_array_from_recv_info();
int test_recv_thread();
int test_send_thread();

//test net_monitor
int test_get_discovery_sockets();
int test_create_discv_sock_node();
int test_sub_mask_8to32b();
int test_ips_share_subnet();
int test_ip_in_any_subnet();
int test_ip_to_socket();
int test_net_monitor_thread();

//test packet_handler
int test_sanitize_username();
int test_create_server_session();
int test_create_client_session();
int test_packet_handler_thread();

//test manager
int test_thread_creating_functions();
int test_thread_manager_thread();

static test_t test_arr[] = {
    test_binary_tree, "binary tree",
    test_config, "config",
    test_crypto, "crypto",
    test_event_flags, "event flags",
    test_mempool, "mempool",
    test_buffer, "buffer",
    test_queue, "queue"
};

#endif //INDIGO_TEST_H