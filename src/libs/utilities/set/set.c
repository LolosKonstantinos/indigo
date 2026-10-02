#include "set.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define IN_RANGE(n,a,b) (n<=a && n>=b)
#define RANGE_CMP(n,a,b) ( IN_RANGE(n,a,b) ? (0) : ((n < b) ? (-1) : (1)) )
typedef struct range_t {
    uint64_t upper;
    uint64_t lower;
}range_t;

typedef struct set_t {
    range_t *pairs;
    uint64_t pairs_size;
    uint64_t *singles;
    uint64_t singles_size;
}set_t;

int new_set(set_t **set)
{
    set_t *nset;

    if (!set) return -1;

    nset = malloc(sizeof(set_t));
    if(!nset) {
        *set = NULL;
        return -1;
    }
    nset->pairs = NULL;
    nset->pairs_size = 0;
    nset->singles = NULL;
    nset->singles_size = 0;

    *set = nset;
    return 0;
}
int free_set(set_t **set)
{
    if(!set) return -1;
    free((*set)->pairs);
    free((*set)->singles);
    free(*set);
    *set = NULL;
    return 0;
}

int set_add(set_t *set, const int64_t n)
{
    uint64_t mid;
    uint64_t bot_singles = 0;
    uint64_t bot_pairs = 0;
    uint64_t top;
    char singles_up = 0;
    char singles_down = 0;
    char pairs_up = 0;
    char pairs_down = 0;
    char collision_count = 0;
    void *tmp_array;


    if (!set) return -1;

    //search for n in singles
    if (set->singles_size > 0) {
        bot_singles = 0;
        top = set->singles_size;

        while (top > 1)
        {
            mid = top / 2;

            if (n >= set->singles[bot_singles + mid])
                bot_singles += mid;

            top -= mid;
        }

        if (n == set->singles[bot_singles])
            return 0;


        if (n - 1 == set->singles[bot_singles]) {
            singles_down = 1;
            ++collision_count;
        }
        if (n + 1 == set->singles[bot_singles + 1]) {
            singles_up = 1;
            ++collision_count;
        }
    }

    //search in the pairs
    if (set->pairs_size > 0) {
        bot_pairs = 0;
        top = set->pairs_size;

        while (top > 1)
        {
            mid = top / 2;
            if (RANGE_CMP(n, set->pairs[bot_pairs + mid].upper, set->pairs[bot_pairs + mid].lower) >= 0)
                bot_pairs += mid;

            top -= mid;
        }

        if (IN_RANGE(n, set->pairs[bot_pairs].upper, set->pairs[bot_pairs].lower))
            return 0;

        if (n - 1 == set->pairs[bot_pairs].upper) {
            pairs_down = 1;
            ++collision_count;
        }
        if (n + 1 == set->pairs[bot_pairs + 1].lower) {
            pairs_up = 1;
            ++collision_count;
        }
    }


    switch (collision_count) {
        case 0: {
            //just insert one in the singles
            tmp_array = realloc(set->singles, (set->singles_size + 1) * sizeof(void*));
            if (!tmp_array) {
                return -1;
            }
            set->singles = tmp_array;
            if (set->singles_size == 0) {
                memmove(set->singles + bot_singles + 2, set->singles + bot_singles + 1, sizeof(uint64_t) * (set->singles_size - bot_singles - 1));
            }
            set->singles_size += 1;
            set->singles[bot_singles + 1] = n;
            break;
        }
        case 1: {
            //remove the single an insert to pairs
            if (singles_up) {
                tmp_array = realloc(set->pairs, (set->pairs_size + 1) * sizeof(range_t));
                if (!tmp_array) {
                    return -1;
                }
                if (set->singles_size > 1) {
                    memmove(set->singles + bot_singles, set->singles + bot_singles + 1, sizeof(uint64_t) * (set->singles_size - bot_singles - 1));
                }
                tmp_array = realloc(set->singles, (set->singles_size - 1) * sizeof(void*));
                if (!tmp_array) {
                    if (set->singles_size > 1){
                        memmove(set->singles + bot_singles + 1, set->singles + bot_singles, sizeof(uint64_t) * (set->singles_size - bot_singles - 1));
                        set->singles[bot_singles] = n + 1;
                    }
                    tmp_array = realloc(set->pairs, set->pairs_size * sizeof(range_t));
                    if (!tmp_array) return -1;
                    set->pairs = tmp_array;

                    return -1;
                }
                if (set->pairs_size == 0) {
                    memmove(set->pairs + bot_pairs + 2, set->pairs + bot_pairs + 1, sizeof(uint64_t) * (set->pairs_size - bot_pairs - 1));
                }
                set->pairs_size += 1;
                set->singles = tmp_array;
                set->singles_size -= 1;


                set->pairs[bot_pairs + 1].lower = n;
                set->pairs[bot_pairs + 1].upper = n + 1;

            }
            else if (singles_down) {
                tmp_array = realloc(set->pairs, (set->pairs_size + 1) * sizeof(range_t));
                if (!tmp_array) {
                    return -1;
                }
                if (set->singles_size > 1) {
                    memmove(set->singles + bot_singles - 1, set->singles + bot_singles, sizeof(uint64_t) * (set->singles_size - bot_singles));
                }
                tmp_array = realloc(set->singles, (set->singles_size - 1) * sizeof(void*));
                if (!tmp_array) {
                    if (set->singles_size > 1){
                        memmove(set->singles + bot_singles, set->singles + bot_singles - 1, sizeof(uint64_t) * (set->singles_size - bot_singles - 2));
                        set->singles[bot_singles] = n - 1;
                    }
                    tmp_array = realloc(set->pairs, set->pairs_size * sizeof(range_t));
                    if (!tmp_array) return -1;
                    set->pairs = tmp_array;

                    return -1;
                }
                if (set->pairs_size == 0) {
                    memmove(set->pairs + bot_pairs + 2, set->pairs + bot_pairs + 1, sizeof(uint64_t) * (set->pairs_size - bot_pairs - 1));
                }
                set->pairs_size += 1;
                set->singles = tmp_array;
                set->singles_size -= 1;


                set->pairs[bot_pairs + 1].lower = n - 1;
                set->pairs[bot_pairs + 1].upper = n;
            }
            //edit the pair
            else if (pairs_up) {
                set->pairs[bot_pairs + 1].lower = n;
            }
            else if (pairs_down) {
                set->pairs[bot_pairs].upper = n;
            }
            break;
        }
        case 2: {
            //4 cases
            if (singles_up && singles_down) {
                tmp_array = realloc(set->pairs, (set->pairs_size + 1) * sizeof(range_t));
                if (!tmp_array) {
                    return -1;
                }
                set->pairs = tmp_array;

                if (set->singles_size > 2) {
                    memmove(set->singles + bot_singles, set->singles + bot_singles + 2, sizeof(uint64_t) * (set->singles_size - bot_singles - 2));
                }
                tmp_array = realloc(set->singles, (set->singles_size - 2) * sizeof(uint64_t));
                if (!tmp_array) {
                    if (set->singles_size > 2) {
                        memmove(set->singles + bot_singles + 2, set->singles + bot_singles, sizeof(uint64_t) * (set->singles_size - bot_singles - 2));
                        set->singles[bot_singles] = n - 1;
                        set->singles[bot_singles + 1] = n + 1;
                    }
                    tmp_array = realloc(set->pairs, set->pairs_size * sizeof(range_t));
                    if (tmp_array) set->pairs = tmp_array;

                    return -1;
                }
                set->singles = tmp_array;


                memmove(set->pairs + bot_pairs + 2, set->pairs + bot_pairs + 1, sizeof(range_t) * (set->pairs_size - bot_pairs - 1) );
                set->pairs[bot_pairs + 1].lower = n - 1;
                set->pairs[bot_pairs + 1].upper = n + 1;

                set->pairs_size += 1;
                set->singles_size -= 2;
            }
            if (singles_up && pairs_down) {
                if (set->singles_size > 1) {
                    memmove(set->singles + bot_singles + 1, set->singles + bot_singles + 2, sizeof(uint64_t) * (set->singles_size - bot_singles - 2));
                }
                tmp_array = realloc(set->singles, (set->singles_size - 1) * sizeof(uint64_t));
                if (!tmp_array) {
                    if (set->singles_size > 1) {
                        memmove(set->singles + bot_singles + 2, set->singles + bot_singles + 1, sizeof(uint64_t) * (set->singles_size - bot_singles - 2));
                        set->singles[bot_singles + 1] = n + 1;
                    }
                    return -1;
                }
                set->pairs[bot_pairs].upper = n + 1;

                set->singles_size -= 1;
            }
            if (singles_down && pairs_up) {
                if (set->singles_size > 1) {
                    memmove(set->singles + bot_singles, set->singles + bot_singles + 1, sizeof(uint64_t) * (set->singles_size - bot_singles - 1));
                }
                tmp_array = realloc(set->singles, (set->singles_size - 1) * sizeof(uint64_t));
                if (!tmp_array) {
                    if (set->singles_size > 1) {
                        memmove(set->singles + bot_singles + 1, set->singles + bot_singles, sizeof(uint64_t) * (set->singles_size - bot_singles - 1));
                        set->singles[bot_singles] = n - 1;
                    }
                    return -1;
                }
                set->pairs[bot_pairs].lower = n - 1;

                set->singles_size -= 1;
            }
            if (pairs_up && pairs_down) {
                const uint64_t largest_num = set->pairs[bot_pairs + 1].upper;

                memmove(set->pairs + bot_pairs, set->pairs + bot_pairs + 1, sizeof(range_t) * (set->pairs_size - bot_pairs - 1));
                tmp_array = realloc(set->pairs, (set->pairs_size - 1) * sizeof(range_t));
                if (!tmp_array) {
                    memmove(set->pairs + bot_pairs + 1, set->pairs + bot_pairs, sizeof(range_t) * (set->pairs_size - 1) );
                    return -1;
                }
                set->pairs = tmp_array;
                set->pairs[bot_pairs].upper = largest_num;

                set->pairs_size -= 1;
            }
            break;
        }
        default:
            return -1;
    }
    return 0;
}
int set_remove(set_t *set, int64_t n)
{
    return 0;
}

int set_add_range(set_t *set, int64_t from, int64_t to)
{
    return 0;
}
int set_remove_range(set_t *set, int64_t from, int64_t to)
{
    return 0;
}

uint64_t set_get_lowest_not_in_set(set_t *set)
{
    uint64_t lowest_single = 0;
    range_t lowest_pair = {.upper = UINT64_MAX, .lower = UINT64_MAX};

    if (!set) return (uint64_t)(-1);

    if (set->pairs)lowest_pair = set->pairs[0];
    if (set->singles)lowest_single = set->singles[0];

    return (lowest_pair.upper < lowest_single)
    ?((lowest_pair.lower == 0) ? lowest_pair.upper + 1: lowest_pair.lower - 1)
    :((lowest_single == 0) ? lowest_single + 1: lowest_single - 1);
}
uint64_t set_get_highest_not_in_set(set_t *set)
{
    uint64_t highest_single = 0;
    range_t highest_pair = {0};

    if (!set) return (uint64_t)(-1);

    if (set->pairs)highest_pair = set->pairs[set->pairs_size - 1];
    if (set->singles)highest_single = set->singles[set->singles_size - 1];

    return (highest_pair.lower > highest_single)
    ?((highest_pair.upper == UINT64_MAX) ? highest_pair.lower - 1: highest_pair.upper + 1)
    :((highest_single == UINT64_MAX) ? highest_single - 1: highest_single + 1);
}
uint64_t set_get_lowest_in_set(set_t *set)
{
    uint64_t lowest_single = 0;
    range_t lowest_pair = {0};

    if (!set) return (uint64_t)(-1);

    if (set->pairs)lowest_pair = set->pairs[0];
    if (set->singles)lowest_single = set->singles[0];

    return (lowest_pair.upper < lowest_single) ? lowest_pair.lower : lowest_single;
}
uint64_t set_get_highest_in_set(set_t *set)
{
    uint64_t highest_single = 0;
    range_t highest_pair = {0};

    if (!set) return (uint64_t)(-1);

    if (set->pairs)highest_pair = set->pairs[set->pairs_size - 1];
    if (set->singles)highest_single = set->singles[set->singles_size - 1];

    return (highest_pair.lower > highest_single) ? highest_pair.upper : highest_single;
}

int set_search(set_t *set, int64_t n)
{
    set_t s;
    uint64_t mid;
    uint64_t bot;
    uint64_t top;
    if (!set) return 0;
    s = *set;

    if (s.singles_size > 0) {
        bot = 0;
        top = s.singles_size;

        while (top > 1)
        {
            mid = top / 2;

            if (n >= s.singles[bot + mid])
                bot += mid;

            top -= mid;
        }

        if (n == s.singles[bot])
            return 1;
    }
    if (s.pairs_size > 0) {
        bot = 0;
        top = s.pairs_size;

        while (top > 1)
        {
            mid = top / 2;
            if (RANGE_CMP(n, s.pairs[bot + mid].upper, s.pairs[bot + mid].lower) >= 0)
                bot += mid;

            top -= mid;
        }

        if (IN_RANGE(n, s.pairs[bot].upper, s.pairs[bot].lower))
            return 1;
    }
    return 0;
}

int set_is_full(set_t *set);
int set_is_empty(set_t *set);