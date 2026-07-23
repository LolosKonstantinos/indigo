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

#include "config.h"
#include "indigo_types.h"
#include "mempool.h"

#include <binary_tree.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <crypto_utils.h>
#include <net_io.h>

int main(void) {
    printf("testing indigo libraries...\n");
    run_tests(test_arr,8);
    return 0;
}

void run_tests(test_t *tests, const uint64_t count) {
    uint64_t passed = 0;
    int ret;
    if ((tests == NULL) || (count == 0)) return;
    ret = sodium_init();
    if (ret) return;

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
    printf("\n\nTests passed: %lld\n", (long long)passed);
    printf("Tests failed: %lld\n", (long long)(count - passed));
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
    if ((tree->search && tree->search_pin && tree->search_release && tree->insert && tree->remove && tree->priv) == 0)
        return TEST_FAILED;

    //insert 1024 nodes
    for (int i = 0; i < (1<<10) + 1; i++) {
        temp_data = i;
        ret = tree->insert(tree, &temp_data);
        if (ret) {
            return TEST_FAILED;
        }
    }
    if (!is_bts_avl(tree)) {
        printf("1");
        return TEST_FAILED;
    }

    //check if bts property is preserved
    for (int i = 0; i < (1<<10) + 1; i++) {
        temp_data = i;
        ret = tree->search_pin(tree, &temp_data, (void **)&found_data);
        if (ret == 0) {
            return TEST_FAILED;
        }
        if (*found_data != temp_data) {
            return TEST_FAILED;
        }
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
        if (ret == 0) return TEST_FAILED;
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
            if (ret == 0) return TEST_FAILED;
            if (*found_data != temp_data) return TEST_FAILED;
        }
    }
    //test if all nodes are deleted
    if (tree_height(tree) != 0) return TEST_FAILED;
    free_tree(tree);
    return TEST_PASSED;
}

int test_mempool()
{
    mempool_t *pool = NULL;
    size_t cell_count;
    void * blocks[4*(1<<10)] = {0};

    //static pool tests
    pool = new_mempool_manual(1 << 10, sizeof(uint64_t), alignof(uint64_t), 0);
    if (!pool) return TEST_FAILED;

    cell_count = get_mempool_cell_count(pool);

    //allocate the whole pool
    for (int i = 0; i < cell_count + 1; i++) {
        blocks[i] = mempool_salloc(pool);
        if (i < cell_count) {
            if ( blocks[i] == NULL) {
                return TEST_FAILED;
            }
        }
        else {
            if (blocks[i] != NULL){
                return TEST_FAILED;
            }

        }
        if (blocks[i]) {
            *((uint64_t *)blocks[i]) = i ^ 0xabcdefabcdefabcd;
        }
    }

    //test for data integrity
    for (int i = 0; i < cell_count; i++) {
        if (*((uint64_t *)blocks[i]) != (i ^ 0xabcdefabcdefabcd)) return TEST_FAILED;
    }

    //test for collisions
    for (int i = 0; i < cell_count; i++) {
        for (int j = 0; j < cell_count; j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }

    //free the pool
    for (int i = 0; i < cell_count; i++) {
        mempool_free(pool, blocks[i]);
    }


    //go again to check if it still functions as intended
    for (int i = 0; i < cell_count + 1; i++) {
        blocks[i] = mempool_salloc(pool);
        if (i < cell_count) {
            if ( blocks[i] == NULL) {
                return TEST_FAILED;
            }
        }
        else {
            if (blocks[i] != NULL) {
                return TEST_FAILED;
            }
        }
    }
    //test for collisions
    for (int i = 0; i < cell_count; i++) {
        for (int j = 0; j < cell_count; j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }
    //free every other block and go again
    for (int i = 0; i < cell_count; i+=2) {
        mempool_free(pool, blocks[i]);
    }
    //go again to check if it still functions as intended
    for (int i = 0; i < cell_count + 2; i+=2) {
        blocks[i] = mempool_salloc(pool);
        if (i < cell_count) {
            if ( blocks[i] == NULL) return TEST_FAILED;
        }
        else {
            if (blocks[i] != NULL) return TEST_FAILED;
        }
    }
    //test for collisions
    for (int i = 0; i < cell_count; i++) {
        for (int j = 0; j < cell_count; j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }
    free_mempool(pool);

    //test dynamic pool
    pool = new_mempool_manual(1 << 10, sizeof(uint64_t), alignof(uint64_t), 0.5f);
    if (!pool) return TEST_FAILED;
    //allocate the whole pool
    for (int i = 0; i < 4 * (1<<10); i++) {
        blocks[i] = mempool_dalloc(pool);
        if ( blocks[i] == NULL) return TEST_FAILED;
        if (blocks[i]) {
            *((uint64_t *)blocks[i]) = i ^ 0xabcdefabcdefabcd;
        }
    }

    //test for data integrity
    for (int i = 0; i < 4*(1<<10) ; i++) {
        if (*((uint64_t *)blocks[i]) != (i ^ 0xabcdefabcdefabcd)) return TEST_FAILED;
    }

    //test for collisions
    for (int i = 0; i < 4*(1<<10); i++) {
        for (int j = 0; j < 4*(1<<10); j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }

    //free the pool
    for (int i = 0; i < 4*(1<<10); i++) {
        mempool_free(pool, blocks[i]);
    }

    //go again to check if it still functions as intended
    for (int i = 0; i < 4*(1<<10); i++) {
        blocks[i] = mempool_dalloc(pool);
        if ( blocks[i] == NULL) return TEST_FAILED;

    }
    //test for collisions
    for (int i = 0; i < 4*(1<<10); i++) {
        for (int j = 0; j < 4*(1<<10); j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }
    //free every other block and go again
    for (int i = 0; i < 4*(1<<10); i+=2) {
        mempool_free(pool, blocks[i]);
    }
    //go again to check if it still functions as intended
    for (int i = 0; i < 4*(1<<10); i+=2) {
        blocks[i] = mempool_dalloc(pool);
        if ( blocks[i] == NULL) return TEST_FAILED;
    }
    //test for collisions
    for (int i = 0; i < 2*(1<<10); i++) {
        for (int j = 0; j < 2*(1<<10); j++) {
            if (i == j) continue;
            if (blocks[i] == blocks[j]) return TEST_FAILED;
        }
    }

    return TEST_PASSED;
}
int test_signature()
{
    packet_t packet;
    init_packet_data_t *packet_data = NULL;
    signing_key_pair_t sign_key_pair;
    char username[MAX_USERNAME_LEN * sizeof(uint32_t) + 1];
    void *master_key = NULL;
    int ret = 0;

    ret = bypass_password(&master_key);
    if (ret) return TEST_FAILED;
    ret = load_signing_key_pair(&sign_key_pair, master_key);
    if (ret) return TEST_FAILED;
    ret = load_username(username);
    if (ret) return TEST_FAILED;

    packet_data = (init_packet_data_t *)packet.data;

    build_packet(&packet, MSG_INIT_PACKET, sign_key_pair.public, NULL, NULL, 0);
    strncpy((char *)packet_data->username, (char *)username, MAX_USERNAME_LEN * sizeof(uint32_t));

    packet_data->timestamp = time(NULL);
    ret = crypto_sign_detached(packet_data->signature, NULL, (unsigned char *)&packet,
        offsetof(packet_t, data) + offsetof(init_packet_data_t, signature),sign_key_pair.secret);
    if (ret) return TEST_FAILED;

    ret = crypto_sign_verify_detached(((init_packet_data_t *)packet.data)->signature, (unsigned char *)&packet,
                            offsetof(packet_t, data) + offsetof(init_packet_data_t, signature), packet.id);
    if (ret) return TEST_FAILED;

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

