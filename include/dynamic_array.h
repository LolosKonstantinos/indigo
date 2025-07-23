

#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


typedef struct dynamic_array {
    void *array;
    size_t size;
    size_t sizeofelement;
    pthread_mutex_t mutex;
}DYNAMIC_ARRAY, VECTOR, DynArray, dyn_array;

//initialize and destroy the array
int dyn_array_init(dyn_array *array, size_t sizeofelement);
void dyn_array_destroy(dyn_array *array);

//general functions
int dyn_array_add(dyn_array *array, void *element);
int dyn_array_remove(dyn_array *array, size_t index);
void *dyn_array_get(dyn_array *array, size_t index);


#endif //DYNAMIC_ARRAY_H
