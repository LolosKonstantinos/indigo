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

#include "tui/tui.h"
#include "indigo_errors.h"
#include "config.h"
#include "indigo_types.h"
#include "logger.h"
#include "manager.h"
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
    sigset_t sigset;

    // network
    uint16_t port;
    uint32_t multicast_addr;

    FILE *log_file = NULL;

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

    //block window change signal for all thread (we allow only ui thread to have it unblocked)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGWINCH);

    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    inet_pton(AF_INET, MULTICAST_ADDR, &multicast_addr);
    port = PORT;

    ret = thread_manager(multicast_addr, port);
    if (ret != INDIGO_SUCCESS) {
        log_error("[main] create_thread_manager_thread failed\n");
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}
