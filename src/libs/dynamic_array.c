//
// Created by Κωνσταντίνος on 7/22/2025.
//

#include "dynamic_array.h"
#include <string.h>

int dyn_array_init(dyn_array *array, const size_t sizeofelement) {
    if (array == NULL) return 1;

    array->size = 0;
    array->sizeofelement = sizeofelement;
    array->array = NULL;

    if(pthread_mutex_init(&(array->mutex), NULL) != 0) return 1;
    return 0;
}

void dyn_array_destroy(dyn_array *array) {
    pthread_mutex_destroy(&(array->mutex));
    free(array->array);
}

int dyn_array_add(dyn_array *array, const void *element) {
    if (array == NULL || element == NULL) return 1;

    void *temp = NULL;
    pthread_mutex_lock(&(array->mutex));

    temp = realloc(array->array, (array->sizeofelement) * ((array->size) + 1));
    if (temp == NULL) {
        pthread_mutex_unlock(&(array->mutex));
        return 1;
    }

    array->array = temp;
    memcpy(&((array->array)[array->size]), element, array->sizeofelement);
    array->size++;
    pthread_mutex_unlock(&(array->mutex));
    return 0;
}
//todo: check if memmove is faster here, memmove accepts overlapping memory
int dyn_array_remove(dyn_array *array,const size_t index) {
    void *temp = NULL;
    if (array == NULL ) return 1;
    if (array->size >= index) return 1;

    //this is the address of the element to be removed
    temp = (array->array) + ((array->sizeofelement) * index);

    pthread_mutex_lock(&(array->mutex));
    for (size_t i = index; i < ((array->size)-1); i++) {
        memcpy(temp,temp+(array->sizeofelement), array->sizeofelement);
        temp += array->sizeofelement;
    }
    (array->size)--;

    temp = realloc(array->array, (array->sizeofelement) * (array->size));
    if (temp == NULL) {
        if (array->size > 0) {
            pthread_mutex_unlock(&(array->mutex));
            return 1;
        }
        if (array->size == 0) {
            array->array = temp; // here temp is NULL
            pthread_mutex_unlock(&(array->mutex));
            return 0;
        }
    }
    array->array = temp;
    pthread_mutex_unlock(&(array->mutex));
    return 0;
}

void *dyn_array_get(dyn_array *array,const size_t index) {
    void *temp = NULL, *ret_obj = NULL;

    if ((array == NULL) || (index >= array->size)) return NULL;

    pthread_mutex_lock(&(array->mutex));

    ret_obj = malloc(array->sizeofelement);

    if (ret_obj == NULL) {
        pthread_mutex_unlock(&(array->mutex));
        return NULL;
    }
    //temp is the address of the element with index "index"
    temp = (array->array) + (array->sizeofelement * index);
    memcpy(ret_obj, temp, array->sizeofelement);

    pthread_mutex_unlock(&(array->mutex));
    return ret_obj;
}

int dyn_array_set(dyn_array *array,const size_t index,const void *element) {
    void *temp = NULL;

    if ((array == NULL) || (index >= array->size)) return 1;

    pthread_mutex_lock(&(array->mutex));

    temp = (array->array) + (array->sizeofelement * index);
    memcpy(temp, element, array->sizeofelement);

    pthread_mutex_unlock(&(array->mutex));

    return 0;
}

void dyn_array_clear(dyn_array *array) {
    pthread_mutex_lock(&(array->mutex));
    free(array->array);
    array->size = 0;
    pthread_mutex_unlock(&(array->mutex));
}