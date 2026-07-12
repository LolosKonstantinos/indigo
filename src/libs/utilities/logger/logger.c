#include "logger.h"
#include <stdatomic.h>

static pthread_mutex_t logger_mutex = PTHREAD_MUTEX_INITIALIZER;
void logger_init()
{
    log_set_lock(logger_lock_callback, &logger_mutex);
    log_set_quiet(true);
}


void logger_lock_callback(bool lock, void *udata)
{
    if (lock) {
        pthread_mutex_lock(udata);
    }
    else {
        pthread_mutex_unlock(udata);
    }
}