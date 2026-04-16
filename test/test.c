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

#include "test.h"

#include <binary_tree.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("testing indigo libraries...\n");
    run_tests(test_arr,7);
    return 0;
}

void run_tests(test_t *tests, const uint64_t count) {
    uint64_t passed = 0;
    int ret;
    if ((tests == NULL) || (count == 0)) return;

    for (uint64_t i = 0; i < count; i++) {
        ret = tests[i].test();
        passed += ret;
        if (ret == TEST_PASSED) {
            printf("%s: PASSED\n", tests[i].name);
        }
        else {
            printf("%s: FAILED\n", tests[i].name);

        }
    }
    printf("\n\nTests passed: %lld\n", passed);
    printf("Tests failed: %lld\n", count - passed);
}

#define DATA_SIZE sizeof(uint64_t)
int bts_cmp(void *a,void *b) {
    if (*(uint64_t *)a == *(uint64_t *)b) return 0;
    if (*(uint64_t *)a > *(uint64_t *)b) return 1;
    return -1;
}
int test_binary_tree() {
    tree_t *tree = NULL;
    uint64_t temp_data = 0;
    uint64_t *found_data = NULL;
    int ret = 0;

    //test if the tree pointer is created and returned
    ret = new_tree(&tree, bts_cmp, DATA_SIZE, BINARY_TREE_FLAG_AVL);
    if (ret) return TEST_FAILED;
    if (tree == NULL) return TEST_FAILED;
    //test if all fields are initialized
    if (!(tree->search && tree->search_pin && tree->search_release && tree->insert && tree->remove && tree->priv))
        return TEST_FAILED;

    //insert 1024 nodes
    for (int i = 0; i < (1<<10) + 1; i++) {
        temp_data = i;
        ret = tree->insert(tree, &temp_data);
        if (ret) return TEST_FAILED;
    }
    if (!is_bts_avl(tree)) return TEST_FAILED;

    //check if bts property is preserved
    for (int i = 0; i < (1<<10) + 1; i++) {
        temp_data = i;
        ret = tree->search_pin(tree, &temp_data, (void **)&found_data);
        if (ret) return TEST_FAILED;
        if (*found_data != temp_data) return TEST_FAILED;
        tree->search_release(tree);
    }
    //remove the root
    temp_data = 511;
    ret = tree->remove(tree, &temp_data);
    if (ret) return TEST_FAILED;
    if (!is_bts_avl(tree)) return TEST_FAILED;

    //check if bts property is preserved
    for (int j = 0; j < (1<<10) + 1; j++) {
        if (j == 511) {
            if (!is_bts_avl(tree)) return TEST_FAILED;
            continue;
        }
        temp_data = j;
        ret = tree->search_pin(tree, &temp_data, (void **)&found_data);
        tree->search_release(tree);
        if (ret) return TEST_FAILED;
        if (*found_data != temp_data) return TEST_FAILED;
    }

    for (int i = 0; i < (1<<10) + 1; i++) {
        if (i == 511) {
            if (!is_bts_avl(tree)) return TEST_FAILED;
            continue;
        }
        temp_data = i;
        ret = tree->remove(tree, &temp_data);
        if (ret) return TEST_FAILED;
        //check if bts property is preserved
        for (int j = i + 1; j < (1<<10) + 1; j++) {
            if (j == 511) continue;
            temp_data = j;
            ret = tree->search_pin(tree, &temp_data, (void **)&found_data);
            tree->search_release(tree);
            if (ret) return TEST_FAILED;
            if (*found_data != temp_data) return TEST_FAILED;
        }
    }
    //test if all nodes are deleted
    if (tree_height(tree) != 0) return TEST_FAILED;
    free_tree(tree);
    return TEST_PASSED;
}

int test_buffer() {
    return TEST_PASSED;
}
int test_config() {
    return TEST_PASSED;
}
int test_crypto() {
    return TEST_PASSED;
}
int test_event_flags() {
    return TEST_PASSED;
}
int test_mempool() {
    return TEST_PASSED;
}
int test_queue() {
    return TEST_PASSED;
}

//test core

//test net_io
int test_send_discovery_packets(){}
int test_register_single_receiver(){}
int test_send_packet(){}
int test_send_file_packet(){}
int test_send_next_file_packet(){}
int test_build_packet(){}
int test_send_info(){}
int test_recv_info(){}
int test_handle_array_from_send_info(){}
int test_handle_array_from_recv_info(){}
int test_recv_thread(){}
int test_send_thread(){}

//test net_monitor
int test_get_discovery_sockets(){}
int test_create_discv_sock_node(){}
int test_sub_mask_8to32b(){}
int test_ips_share_subnet(){}
int test_ip_in_any_subnet(){}
int test_ip_to_socket(){}
int test_net_monitor_thread(){}

//test packet_handler
int test_sanitize_username(){}
int test_create_server_session(){}
int test_create_client_session(){}
int test_packet_handler_thread(){}

//test manager
int test_thread_creating_functions(){}
int test_thread_manager_thread(){}

