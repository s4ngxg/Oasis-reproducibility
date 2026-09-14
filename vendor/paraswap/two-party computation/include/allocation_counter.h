#ifndef OASIS_ALLOCATION_COUNTER_H
#define OASIS_ALLOCATION_COUNTER_H

#include <stddef.h>
#include <stdlib.h>

typedef struct {
  unsigned long long malloc_calls;
  unsigned long long calloc_calls;
  unsigned long long realloc_calls;
  unsigned long long free_calls;
  unsigned long long requested_bytes;
} bench_allocation_metrics_t;

void *bench_counted_malloc(size_t size);
void *bench_counted_calloc(size_t count, size_t size);
void *bench_counted_realloc(void *pointer, size_t size);
void bench_counted_free(void *pointer);
void bench_allocation_metrics_read(bench_allocation_metrics_t *metrics);

#ifndef BENCH_ALLOCATION_COUNTER_IMPLEMENTATION
#define malloc(size) bench_counted_malloc(size)
#define calloc(count, size) bench_counted_calloc((count), (size))
#define realloc(pointer, size) bench_counted_realloc((pointer), (size))
#define free(pointer) bench_counted_free(pointer)
#endif

#endif
