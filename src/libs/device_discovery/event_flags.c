//
// Created by Constantin on 07/08/2025.
//

#include "event_flags.h"
#include <stdlib.h>


//////////////////////////////////////////////////////////////
///                                                        ///
///                  EVENT_FLAG_UTILITIES                  ///
///                                                        ///
//////////////////////////////////////////////////////////////

EFLAG *create_event_flag() {
    EFLAG *event_flag = (EFLAG *)malloc(sizeof(EFLAG));
    if (event_flag == NULL) {
        return NULL;
    }
    pthread_mutex_init(&(event_flag->mutex), NULL);
    pthread_cond_init(&(event_flag->cond), NULL);
    event_flag->event_flag = 0;
    return event_flag;
}

int free_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    // pthread_mutex_lock(&(event_flag->mutex));
    // pthread_cond_broadcast(&(event_flag->cond));
    // pthread_mutex_unlock(&(event_flag->mutex));

    pthread_mutex_lock(&(event_flag->mutex));
    pthread_mutex_destroy(&(event_flag->mutex));
    pthread_mutex_unlock(&(event_flag->mutex));

    pthread_cond_destroy(&(event_flag->cond));

    free(event_flag);
    return 0;
}

int init_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    if (pthread_mutex_init(&(event_flag->mutex), NULL) != 0) return 1;
    if (pthread_cond_init(&(event_flag->cond), NULL) != 0) {
        pthread_mutex_destroy(&(event_flag->mutex));
        return 1;
    }

    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = 0;
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int destroy_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));

    pthread_mutex_destroy(&(event_flag->mutex));
    pthread_cond_destroy(&(event_flag->cond));
    return 0;
}

int set_event_flag(EFLAG *event_flag, const uint32_t flag_value) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = flag_value;
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int update_event_flag(EFLAG *event_flag, const uint32_t flag_value) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag |= flag_value;
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int reset_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = 0;
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int reset_single_event(EFLAG *event_flag, const uint32_t flag_value) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag &= (!flag_value);
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

uint32_t get_event_flag(EFLAG *event_flag) {
    uint32_t fvalue = 0;
    if (event_flag == NULL) return 0;
    pthread_mutex_lock(&(event_flag->mutex));
    fvalue = event_flag->event_flag;
    pthread_mutex_unlock(&(event_flag->mutex));
    return fvalue;
}

uint8_t termination_is_on(EFLAG *event_flag) {
    if (event_flag == NULL) return 0;

    pthread_mutex_lock(&(event_flag->mutex));
    if ((event_flag->event_flag) & EF_TERMINATION) {
        pthread_mutex_unlock(&(event_flag->mutex));
        return 1;
    }
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;

}

//conditions
void wait_on_flag_condition(EFLAG *flag, const uint32_t flag_value, const uint32_t status) {
    pthread_mutex_lock(&(flag->mutex));
    while (((flag->event_flag) & flag_value) ^ status) {
        pthread_cond_wait(&(flag->cond), &(flag->mutex));
    }
    pthread_mutex_unlock(&(flag->mutex));
}