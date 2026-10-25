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

#include "ui/ui.h"
#include "indigo_errors.h"
#include "config.h"
#include "indigo_types.h"
#include "logger.h"
#include "manager.h"
#include "indigo_plugin/indigo_plugin.h"

#include <log.h>

#include <locale.h>
#include <signal.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsaData;
#endif
    int ret = 0;

    // network
    uint16_t port;
    uint32_t multicast_addr;

    uint16_t execution_flags = 0;

    FILE *log_file = NULL;

    void *master_key = NULL;

    pthread_mutex_t *mutex = NULL;
    pthread_cond_t *cond = NULL;
    char *flag = NULL;

    indigo_plugin_t **plugins = NULL;
    size_t plugin_count = 0;


    logger_init();
    log_file = load_log_file();
    if (log_file == NULL) {
        return -1;
    }
    log_add_fp(log_file, LOG_TRACE);

    if (sodium_init() == -1)
        return INDIGO_ERROR_SODIUM_ERROR;

#ifdef _WIN32
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    setlocale(LC_ALL, "");

    ret = verify_user(&master_key);
    if (ret) {
        log_fatal("[main] verify_user() failed\n");
        return ret;
    }

    inet_pton(AF_INET, MULTICAST_ADDR, &multicast_addr);
    port = PORT;

#ifdef __linux
    if (getuid() == 0) {
        execution_flags |= MANAGER_FLAG_PRIVILEGED;
    }
#endif

    ret = load_plugins(&plugins, &plugin_count);
    if (ret != 0) {
        log_warn("[main] load_plugins() failed\n");
        plugin_count = 0;
        plugins = NULL;
    }


    flag = malloc(sizeof(char));
    mutex = malloc(sizeof(pthread_mutex_t));
    cond = malloc(sizeof(pthread_cond_t));
    if (!flag || !mutex || !cond) {
        log_fatal("[main] malloc failed\n");
        free(flag);
        free(mutex);
        free(cond);
        free(plugins);
        return 1;
    }

    *flag = 0;
    ret = pthread_mutex_init(mutex, NULL);
    if(ret != 0) {
        free(flag);
        free(mutex);
        free(cond);
        free(plugins);
        log_fatal("[main] pthread_mutex_init() failed\n");
        return 1;
    }
    ret = pthread_cond_init(cond, NULL);
    if (ret != 0) {
        log_fatal("[main] pthread_cond_init() failed\n");
        free(flag);
        free(mutex);
        free(cond);
        free(plugins);
        pthread_mutex_destroy(mutex);
        return 1;
    }


    ret = create_thread_manager(master_key, port, multicast_addr, execution_flags, mutex, cond, flag, plugins, plugin_count);
    if (ret != INDIGO_SUCCESS) {
        log_fatal("[main] create_thread_manager_thread failed\n");
        pthread_mutex_destroy(mutex);
        pthread_cond_destroy(cond);
        free(flag);
        free(mutex);
        free(cond);
        free(plugins);
        return ret;
    }
    master_key = NULL;

    pthread_mutex_lock(mutex);
    while (pthread_cond_wait(cond, mutex)) {
        if (*flag == -1) {
            pthread_exit(NULL);
        }
        if (*flag == 1) {
            break;
        }
    }

    pthread_mutex_unlock(mutex);

    pthread_mutex_destroy(mutex);
    pthread_cond_destroy(cond);
    free(flag);
    free(mutex);
    free(cond);
    flag = NULL;
    mutex = NULL;
    cond = NULL;

    //run the ui
    start_indigo_ui();

#ifdef _WIN32
    WSACleanup();
#endif

    pthread_exit(NULL);
}
