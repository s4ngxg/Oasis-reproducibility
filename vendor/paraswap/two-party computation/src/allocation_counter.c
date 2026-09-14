#define BENCH_ALLOCATION_COUNTER_IMPLEMENTATION

#include <stdatomic.h>

#include "allocation_counter.h"

static _Atomic unsigned long long malloc_calls;
static _Atomic unsigned long long calloc_calls;
static _Atomic unsigned long long realloc_calls;
static _Atomic unsigned long long free_calls;
static _Atomic unsigned long long requested_bytes;

void *bench_counted_malloc(size_t size) {
  atomic_fetch_add_explicit(&malloc_calls, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&requested_bytes, size, memory_order_relaxed);
  return malloc(size);
}

void *bench_counted_calloc(size_t count, size_t size) {
  atomic_fetch_add_explicit(&calloc_calls, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&requested_bytes, count * size,
                            memory_order_relaxed);
  return calloc(count, size);
}

void *bench_counted_realloc(void *pointer, size_t size) {
  atomic_fetch_add_explicit(&realloc_calls, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&requested_bytes, size, memory_order_relaxed);
  return realloc(pointer, size);
}

void bench_counted_free(void *pointer) {
  atomic_fetch_add_explicit(&free_calls, 1, memory_order_relaxed);
  free(pointer);
}

void bench_allocation_metrics_read(bench_allocation_metrics_t *metrics) {
  if (metrics == NULL) return;
  metrics->malloc_calls = atomic_load_explicit(&malloc_calls,
                                                memory_order_relaxed);
  metrics->calloc_calls = atomic_load_explicit(&calloc_calls,
                                                memory_order_relaxed);
  metrics->realloc_calls = atomic_load_explicit(&realloc_calls,
                                                 memory_order_relaxed);
  metrics->free_calls = atomic_load_explicit(&free_calls,
                                              memory_order_relaxed);
  metrics->requested_bytes = atomic_load_explicit(&requested_bytes,
                                                   memory_order_relaxed);
}
