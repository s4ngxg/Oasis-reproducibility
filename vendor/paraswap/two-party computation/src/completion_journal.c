#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "completion_journal.h"

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static unsigned long temporary_counter;

static int write_all(int descriptor, const uint8_t *data, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(descriptor, data + offset, length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return RLC_ERR;
    offset += (size_t) written;
  }
  return RLC_OK;
}

static int read_exact(int descriptor, uint8_t *data, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t received = read(descriptor, data + offset, length - offset);
    if (received < 0 && errno == EINTR) continue;
    if (received <= 0) return RLC_ERR;
    offset += (size_t) received;
  }
  {
    uint8_t extra;
    ssize_t received;
    do {
      received = read(descriptor, &extra, 1);
    } while (received < 0 && errno == EINTR);
    if (received != 0) return RLC_ERR;
  }
  return RLC_OK;
}

static int completion_path(
    char *out, size_t out_size, const char *directory, unsigned pair_id,
    uint64_t execution_id, const uint8_t sid[BENCH_DIGEST_BYTES]) {
  char sid_hex[2 * BENCH_DIGEST_BYTES + 1];
  size_t i;
  int written;
  if (out == NULL || out_size == 0 || directory == NULL ||
      directory[0] == '\0' || sid == NULL) return RLC_ERR;
  for (i = 0; i < BENCH_DIGEST_BYTES; i++) {
    static const char digits[] = "0123456789abcdef";
    sid_hex[2 * i] = digits[sid[i] >> 4];
    sid_hex[2 * i + 1] = digits[sid[i] & 15u];
  }
  sid_hex[2 * BENCH_DIGEST_BYTES] = '\0';
  written = snprintf(out, out_size, "%s/p%u-e%llu-s%s.done", directory,
                     pair_id, (unsigned long long) execution_id, sid_hex);
  return written > 0 && (size_t) written < out_size ? RLC_OK : RLC_ERR;
}

static int validate_done(
    const uint8_t *frame, size_t length, unsigned pair_id,
    uint64_t execution_id, const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t expected_completion_digest[BENCH_DIGEST_BYTES]) {
  bench_header_t header;
  if (frame == NULL || length != BENCH_COMPLETION_FRAME_BYTES ||
      bench_read_header(frame, length, &header) != RLC_OK ||
      header.type != BENCH_MSG_DONE || header.count == 0 ||
      header.pair_id != pair_id || header.first_ordinal != 0 ||
      header.execution_id != execution_id ||
      !bench_digest_equal(header.sid, sid)) return RLC_ERR;
  if (expected_completion_digest != NULL &&
      !bench_digest_equal(frame + BENCH_HEADER_SIZE,
                          expected_completion_digest)) return RLC_ERR;
  return RLC_OK;
}

int bench_completion_journal_prepare(const char *directory) {
  struct stat metadata;
  if (directory == NULL || directory[0] == '\0') return RLC_ERR;
  if (mkdir(directory, 0700) != 0 && errno != EEXIST) return RLC_ERR;
  if (lstat(directory, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
      S_ISLNK(metadata.st_mode)) return RLC_ERR;
  if ((metadata.st_mode & 0077) != 0 && chmod(directory, 0700) != 0)
    return RLC_ERR;
  return RLC_OK;
}

int bench_completion_journal_load(
    const char *directory, unsigned pair_id, uint64_t execution_id,
    const uint8_t sid[BENCH_DIGEST_BYTES],
    const uint8_t expected_completion_digest[BENCH_DIGEST_BYTES],
    uint8_t done_frame[BENCH_COMPLETION_FRAME_BYTES]) {
  char path[BENCH_AUTH_PATH_BYTES + 128];
  struct stat metadata;
  int descriptor;
  int status = RLC_ERR;
  if (done_frame == NULL ||
      completion_path(path, sizeof(path), directory, pair_id, execution_id,
                      sid) != RLC_OK) return RLC_ERR;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return RLC_ERR;
  if (fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
      metadata.st_size == (off_t) BENCH_COMPLETION_FRAME_BYTES &&
      read_exact(descriptor, done_frame, BENCH_COMPLETION_FRAME_BYTES) == RLC_OK &&
      validate_done(done_frame, BENCH_COMPLETION_FRAME_BYTES, pair_id,
                    execution_id, sid, expected_completion_digest) == RLC_OK) {
    status = RLC_OK;
  }
  close(descriptor);
  return status;
}

int bench_completion_journal_store(
    const char *directory, const uint8_t *done_frame, size_t done_length) {
  bench_header_t header;
  char target[BENCH_AUTH_PATH_BYTES + 128];
  char temporary[BENCH_AUTH_PATH_BYTES + 160];
  uint8_t existing[BENCH_COMPLETION_FRAME_BYTES];
  int descriptor = -1;
  int directory_descriptor = -1;
  int status = RLC_ERR;
  int written;
  if (done_frame == NULL || done_length != BENCH_COMPLETION_FRAME_BYTES ||
      bench_read_header(done_frame, done_length, &header) != RLC_OK ||
      validate_done(done_frame, done_length, header.pair_id,
                    header.execution_id, header.sid, NULL) != RLC_OK ||
      bench_completion_journal_prepare(directory) != RLC_OK ||
      completion_path(target, sizeof(target), directory, header.pair_id,
                      header.execution_id, header.sid) != RLC_OK) return RLC_ERR;

  written = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%lu", target,
                     (long) getpid(), ++temporary_counter);
  if (written <= 0 || (size_t) written >= sizeof(temporary)) return RLC_ERR;
  descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) return RLC_ERR;
  if (write_all(descriptor, done_frame, done_length) != RLC_OK ||
      fsync(descriptor) != 0) goto cleanup;
  if (close(descriptor) != 0) {
    descriptor = -1;
    goto cleanup;
  }
  descriptor = -1;

  if (link(temporary, target) != 0) {
    if (errno != EEXIST ||
        bench_completion_journal_load(
            directory, header.pair_id, header.execution_id, header.sid,
            done_frame + BENCH_HEADER_SIZE, existing) != RLC_OK ||
        memcmp(existing, done_frame, done_length) != 0) goto cleanup;
  }
  directory_descriptor = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (directory_descriptor < 0 || fsync(directory_descriptor) != 0)
    goto cleanup;
  status = RLC_OK;

cleanup:
  if (descriptor >= 0) close(descriptor);
  if (directory_descriptor >= 0) close(directory_descriptor);
  unlink(temporary);
  return status;
}
