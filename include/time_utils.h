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
#ifndef INDIGO_TIME_UTILS_H
#define INDIGO_TIME_UTILS_H

#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

#define BILLION  1000000000L
#define MILLION  1000000L
#define THOUSAND 1000L

#define nstos(t)  ((t)/BILLION)
#define stons(t)  ((t)*BILLION)
#define nstoms(t) ((t)/MILLION)
#define mstons(t) ((t)*MILLION)
#define mstos(t)  ((t)/THOUSAND)
#define stoms(t)  ((t)*THOUSAND)


static FORCE_INLINE struct timespec timespec_diff(const struct timespec *const a,const struct timespec *const b)
{
    const time_t sec = a->tv_sec - b->tv_sec;
    long nsec = a->tv_nsec - b->tv_nsec;
    const long cond = (nsec>>(sizeof(long) * CHAR_BIT - 1)) ^ (sec>>(sizeof(time_t) * CHAR_BIT - 1));
    nsec = labs(nsec);

    return (struct timespec){
        .tv_sec = labs(sec) - (1 & cond),
        .tv_nsec = nsec - ((2*nsec - BILLION) & cond)
    };
}

static FORCE_INLINE int timespec_cmp(const struct timespec *const a, const struct timespec *const b)
{
    if (a->tv_sec != b->tv_sec) {
        return (a->tv_sec > b->tv_sec) - (a->tv_sec < b->tv_sec);
    }
    return (a->tv_nsec > b->tv_nsec) - (a->tv_nsec < b->tv_nsec);
}

static FORCE_INLINE struct timespec min_timespec(const struct timespec *const a, const struct timespec *const b)
{
    return timespec_cmp(a, b) == -1 ? *a : *b;
}

static FORCE_INLINE void timespec_add(struct timespec *const a, const struct timespec *const b)
{
    long final_ns = (a->tv_nsec + b->tv_nsec) % BILLION;
    a->tv_sec += b->tv_sec + (a->tv_nsec + b->tv_nsec - final_ns)/BILLION;
    a->tv_nsec = final_ns;
}

static inline struct timespec mstotimespec(const uint64_t ms)
{
    long ns = (long)(ms%THOUSAND);
    return (struct timespec){.tv_sec = mstos(ms-ns), .tv_nsec = mstons(ns)};
}

static inline struct timespec stotimespec(const time_t s)
{
    return (struct timespec){.tv_sec = s, .tv_nsec = 0};
}

static inline struct timespec nstotimespec(const uint64_t ns)
{
    long final_ns = (long)(ns%BILLION);
    return (struct timespec){.tv_sec = nstos(ns-final_ns), .tv_nsec = final_ns};
}

#endif // INDIGO_TIME_UTILS_H
