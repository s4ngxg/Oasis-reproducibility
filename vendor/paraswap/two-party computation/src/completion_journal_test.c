#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "completion_journal.h"

static int fail_sync;
static int fail_directory_sync;
static unsigned directory_sync_failures;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
  struct stat metadata;
  if (fail_sync) { errno=EIO; return -1; }
  if (fail_directory_sync && fstat(fd,&metadata)==0 &&
      S_ISDIR(metadata.st_mode)) {
    directory_sync_failures++;
    errno=EIO;
    return -1;
  }
  return __real_fsync(fd);
}

static int descriptor_count(void) {
  DIR *stream=opendir("/proc/self/fd");
  struct dirent *entry;
  int count=0;
  if (!stream) return -1;
  while ((entry=readdir(stream))!=NULL)
    if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) count++;
  closedir(stream);
  return count;
}

static void cleanup_directory(const char *directory) {
  DIR *stream = opendir(directory);
  struct dirent *entry;
  if (stream == NULL) return;
  while ((entry = readdir(stream)) != NULL) {
    char path[BENCH_AUTH_PATH_BYTES + 160];
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) > 0)
      unlink(path);
  }
  closedir(stream);
  rmdir(directory);
}

int main(void) {
  char directory[] = "/tmp/oasis-completion-journal-test-XXXXXX";
  uint8_t sid[BENCH_DIGEST_BYTES];
  uint8_t other_sid[BENCH_DIGEST_BYTES];
  uint8_t digest[BENCH_DIGEST_BYTES];
  uint8_t other_digest[BENCH_DIGEST_BYTES];
  uint8_t done[BENCH_COMPLETION_FRAME_BYTES];
  uint8_t conflict[BENCH_COMPLETION_FRAME_BYTES];
  uint8_t loaded[BENCH_COMPLETION_FRAME_BYTES];
  int status = 1;
  memset(sid, 0x11, sizeof(sid));
  memset(other_sid, 0x12, sizeof(other_sid));
  memset(digest, 0x22, sizeof(digest));
  memset(other_digest, 0x23, sizeof(other_digest));
  if (mkdtemp(directory) == NULL) return 1;

  bench_write_header_sid(done, BENCH_MSG_DONE, 5, 7, 0, 99, sid);
  memcpy(done + BENCH_HEADER_SIZE, digest, sizeof(digest));
  memcpy(conflict, done, sizeof(conflict));
  memcpy(conflict + BENCH_HEADER_SIZE, other_digest, sizeof(other_digest));

  int descriptors_before=descriptor_count();
  if (descriptors_before<0) goto cleanup;
  fail_sync=1;
  for (unsigned attempt=0;attempt<16;attempt++)
    if (bench_completion_journal_store(directory,done,sizeof(done))==RLC_OK)
      goto cleanup;
  fail_sync=0;
  if (descriptor_count()!=descriptors_before ||
      bench_completion_journal_load(directory,7,99,sid,digest,loaded)==RLC_OK)
    goto cleanup;

  /* A visible link is not a durable completion until directory fsync succeeds. */
  fail_directory_sync=1;
  for (unsigned attempt=0;attempt<16;attempt++) {
    if (bench_completion_journal_store(directory,done,sizeof(done))==RLC_OK ||
        bench_completion_journal_load(directory,7,99,sid,digest,loaded)!=RLC_OK ||
        memcmp(done,loaded,sizeof(done))!=0)
      goto cleanup;
  }
  if (directory_sync_failures!=16 || descriptor_count()!=descriptors_before)
    goto cleanup;
  fail_directory_sync=0;

  if (bench_completion_journal_prepare(directory) != RLC_OK ||
      bench_completion_journal_store(directory, done, sizeof(done)) != RLC_OK ||
      bench_completion_journal_store(directory, done, sizeof(done)) != RLC_OK ||
      bench_completion_journal_load(directory, 7, 99, sid, digest, loaded) !=
          RLC_OK ||
      memcmp(done, loaded, sizeof(done)) != 0 ||
      bench_completion_journal_load(directory, 7, 99, sid, other_digest,
                                    loaded) == RLC_OK ||
      bench_completion_journal_load(directory, 7, 99, other_sid, digest,
                                    loaded) == RLC_OK ||
      bench_completion_journal_load(directory, 8, 99, sid, digest, loaded) ==
          RLC_OK ||
      bench_completion_journal_store(directory, conflict, sizeof(conflict)) ==
          RLC_OK ||
      bench_completion_journal_store(directory, done, sizeof(done) - 1) ==
          RLC_OK) {
    goto cleanup;
  }
  /* Same session/digest but a different item count is not an idempotent DONE. */
  memcpy(conflict, done, sizeof(conflict));
  bench_write_header_sid(conflict, BENCH_MSG_DONE, 6, 7, 0, 99, sid);
  if (bench_completion_journal_store(directory, conflict, sizeof(conflict)) == RLC_OK ||
      bench_completion_journal_load(directory, 7, 99, sid, digest, loaded) != RLC_OK ||
      memcmp(done, loaded, sizeof(done)) != 0) goto cleanup;
  bench_write_header_sid(done, BENCH_MSG_ABORT, 5, 7, 0, 99, sid);
  memcpy(done + BENCH_HEADER_SIZE, digest, sizeof(digest));
  if (bench_completion_journal_store(directory, done, sizeof(done)) == RLC_OK)
    goto cleanup;

  printf("COMPLETION_JOURNAL_TEST atomic=pass idempotent=pass "
         "mismatch=reject conflict=reject fsync_failure=reject "
         "directory_sync_retry=pass fd_leak=none\n");
  status = 0;

cleanup:
  cleanup_directory(directory);
  return status;
}
