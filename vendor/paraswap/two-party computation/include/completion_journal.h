#ifndef OASIS_COMPLETION_JOURNAL_H
#define OASIS_COMPLETION_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "preswap_protocol.h"

int bench_completion_journal_prepare(const char *directory);

int bench_completion_journal_store(
    const char *directory, const uint8_t *done_frame, size_t done_length);

int bench_completion_journal_load(
    const char *directory, unsigned pair_id, uint64_t execution_id,
    const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t expected_completion_digest[BENCH_DIGEST_BYTES],
    uint8_t done_frame[BENCH_COMPLETION_FRAME_BYTES]);

#endif
