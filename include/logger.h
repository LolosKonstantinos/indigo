#ifndef INDIGO_LOGGER_H
#define INDIGO_LOGGER_H

#include <log.h>
#include <pthread.h>



void logger_init();
int logger_cleanup();

void logger_lock_callback(bool lock, void *udata);

#endif // INDIGO_LOGGER_H
