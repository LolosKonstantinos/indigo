#ifndef INDIGO_SET_H
#define INDIGO_SET_H

#include <stdint.h>
#define is_in_set(set,n) (set_search(set,n))
#define not_in_set(set,n) (set_search(set,n) == 0)

typedef  struct set_t set_t;

int new_set(set_t **set);
int free_set(set_t **set);

int set_add(set_t *sett, int64_t n);
int set_remove(set_t *set, int64_t n);

int set_add_range(set_t *set, int64_t from, int64_t to);
int set_remove_range(set_t *set, int64_t from, int64_t to);

uint64_t set_get_lowest_not_in_set(set_t *set);
uint64_t set_get_highest_not_in_set(set_t *set);
uint64_t set_get_lowest_in_set(set_t *set);
uint64_t set_get_highest_in_set(set_t *set);

int set_search(set_t *set, int64_t n);

int set_is_full(set_t *set);
int set_is_empty(set_t *set);

#endif // INDIGO_SET_H
