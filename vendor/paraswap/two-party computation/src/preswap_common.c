#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "zmq.h"
#include "preswap_protocol.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

const char *bench_mode_name(bench_mode_t mode) {
  switch (mode) {
    case BENCH_MODE_ORIGINAL_ITEMWISE:
      return "reference-itemwise";
    case BENCH_MODE_PHASE_COALESCED_ITEMWISE:
      return "phase-coalesced-itemwise";
    case BENCH_MODE_BJP_ITEMWISE:
      return "batch-joint-presigning-itemwise";
    case BENCH_MODE_PHASE_COALESCED_MSM:
      return "phase-coalesced-batch-verification";
    case BENCH_MODE_BJP_MSM:
      return "batch-joint-presigning-batch-verification";
    default:
      return "unknown";
  }
}

long long bench_monotonic_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (long long) value.tv_sec * 1000000000LL + value.tv_nsec;
}

static long long timeval_ns(struct timeval value) {
  return (long long) value.tv_sec * 1000000000LL +
         (long long) value.tv_usec * 1000LL;
}

static int schedstat_mark(long long *wait_ns, long long *slices) {
  FILE *stream;
  unsigned long long runtime_value;
  unsigned long long wait_value;
  unsigned long long slice_value;
  if (wait_ns == NULL || slices == NULL) return RLC_ERR;
  stream = fopen("/proc/self/schedstat", "r");
  if (stream == NULL) return RLC_ERR;
  if (fscanf(stream, "%llu %llu %llu", &runtime_value, &wait_value,
             &slice_value) != 3) {
    fclose(stream);
    return RLC_ERR;
  }
  fclose(stream);
  (void) runtime_value;
  *wait_ns = (long long) wait_value;
  *slices = (long long) slice_value;
  return RLC_OK;
}

int bench_resource_mark(bench_resource_mark_t *mark) {
  struct rusage usage;
  if (mark == NULL || getrusage(RUSAGE_SELF, &usage) != 0 ||
      schedstat_mark(&mark->scheduler_wait_ns,
                     &mark->scheduler_slices) != RLC_OK) return RLC_ERR;
  mark->user_cpu_ns = timeval_ns(usage.ru_utime);
  mark->system_cpu_ns = timeval_ns(usage.ru_stime);
  mark->max_rss_kb = usage.ru_maxrss;
  mark->voluntary_context_switches = usage.ru_nvcsw;
  mark->involuntary_context_switches = usage.ru_nivcsw;
  return RLC_OK;
}

void bench_resource_delta(const bench_resource_mark_t *before,
                          const bench_resource_mark_t *after,
                          bench_resource_mark_t *delta) {
  if (before == NULL || after == NULL || delta == NULL) return;
  delta->user_cpu_ns = after->user_cpu_ns - before->user_cpu_ns;
  delta->system_cpu_ns = after->system_cpu_ns - before->system_cpu_ns;
  delta->max_rss_kb = after->max_rss_kb;
  delta->voluntary_context_switches =
      after->voluntary_context_switches - before->voluntary_context_switches;
  delta->involuntary_context_switches =
      after->involuntary_context_switches -
      before->involuntary_context_switches;
  delta->scheduler_wait_ns =
      after->scheduler_wait_ns - before->scheduler_wait_ns;
  delta->scheduler_slices =
      after->scheduler_slices - before->scheduler_slices;
}

int bench_mode_is_coalesced(bench_mode_t mode) {
  return mode != BENCH_MODE_ORIGINAL_ITEMWISE;
}

int bench_mode_is_bjp(bench_mode_t mode) {
  return mode == BENCH_MODE_BJP_ITEMWISE || mode == BENCH_MODE_BJP_MSM;
}

int bench_mode_has_item_sessions(bench_mode_t mode) {
  return mode == BENCH_MODE_PHASE_COALESCED_ITEMWISE ||
         mode == BENCH_MODE_PHASE_COALESCED_MSM;
}

int bench_mode_uses_msm(bench_mode_t mode) {
  return mode == BENCH_MODE_PHASE_COALESCED_MSM || mode == BENCH_MODE_BJP_MSM;
}

int bench_mode_uses_explicit_nonce(bench_mode_t mode) {
  return mode != BENCH_MODE_ORIGINAL_ITEMWISE;
}

size_t bench_request_bytes(bench_mode_t mode) {
  size_t size = bench_mode_uses_explicit_nonce(mode)
                    ? BENCH_EXPLICIT_REQUEST_BYTES
                    : BENCH_LEGACY_REQUEST_BYTES;
  return size + (bench_mode_has_item_sessions(mode)
                     ? BENCH_ITEM_SESSION_BYTES : 0);
}

size_t bench_response_bytes(bench_mode_t mode) {
  size_t size = bench_mode_uses_explicit_nonce(mode)
                    ? BENCH_EXPLICIT_RESPONSE_BYTES
                    : BENCH_LEGACY_RESPONSE_BYTES;
  return size + (bench_mode_has_item_sessions(mode)
                     ? BENCH_ITEM_SESSION_BYTES : 0);
}

size_t bench_final_bytes(bench_mode_t mode) {
  size_t size = bench_mode_uses_explicit_nonce(mode)
                    ? BENCH_EXPLICIT_FINAL_BYTES
                    : BENCH_SIG_BYTES;
  return size + (bench_mode_has_item_sessions(mode)
                     ? BENCH_ITEM_SESSION_BYTES : 0);
}

size_t bench_open_prefix_bytes(bench_mode_t mode) {
  return bench_mode_uses_explicit_nonce(mode) ? 0 : BENCH_SALT_BYTES;
}

size_t bench_done_bytes(bench_mode_t mode) {
  return BENCH_DIGEST_BYTES +
         (bench_mode_uses_explicit_nonce(mode) && !bench_mode_uses_msm(mode)
              ? BENCH_SALT_BYTES : 0);
}

static int parse_uint(const char *value, unsigned *out) {
  char *end = NULL;
  unsigned long parsed = strtoul(value, &end, 10);
  if (value == end || end == NULL || *end != '\0' || parsed > UINT32_MAX) {
    return RLC_ERR;
  }
  *out = (unsigned) parsed;
  return RLC_OK;
}

static int parse_u64(const char *value, uint64_t *out) {
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (value == end || end == NULL || *end != '\0') {
    return RLC_ERR;
  }
  *out = (uint64_t) parsed;
  return RLC_OK;
}

static int copy_endpoint_host(char out[BENCH_ENDPOINT_HOST_BYTES],
                              const char *value) {
  size_t length;
  if (value == NULL || value[0] == '\0') return RLC_ERR;
  length = strlen(value);
  if (length >= BENCH_ENDPOINT_HOST_BYTES) return RLC_ERR;
  memcpy(out, value, length + 1);
  return RLC_OK;
}

static int copy_auth_value(char *out, size_t out_size, const char *value) {
  size_t length;
  if (out == NULL || out_size == 0 || value == NULL || value[0] == '\0') {
    return RLC_ERR;
  }
  length = strlen(value);
  if (length >= out_size) return RLC_ERR;
  memcpy(out, value, length + 1);
  return RLC_OK;
}

static int copy_ipc_endpoint(char *out, size_t out_size, const char *value) {
  if (copy_auth_value(out, out_size, value) != RLC_OK ||
      strncmp(value, "ipc://", sizeof("ipc://") - 1) != 0) {
    return RLC_ERR;
  }
  return RLC_OK;
}

static int parse_hex_digest(const char *value,
                            uint8_t out[BENCH_DIGEST_BYTES]) {
  size_t i;
  if (value == NULL || strlen(value) != 2 * BENCH_DIGEST_BYTES) return RLC_ERR;
  for (i = 0; i < BENCH_DIGEST_BYTES; i++) {
    unsigned high;
    unsigned low;
    char a = value[2 * i];
    char b = value[2 * i + 1];
    high = a >= '0' && a <= '9' ? (unsigned) (a - '0')
           : a >= 'a' && a <= 'f' ? (unsigned) (a - 'a' + 10)
           : a >= 'A' && a <= 'F' ? (unsigned) (a - 'A' + 10)
                                  : 16;
    low = b >= '0' && b <= '9' ? (unsigned) (b - '0')
          : b >= 'a' && b <= 'f' ? (unsigned) (b - 'a' + 10)
          : b >= 'A' && b <= 'F' ? (unsigned) (b - 'A' + 10)
                                 : 16;
    if (high > 15 || low > 15) return RLC_ERR;
    out[i] = (uint8_t) ((high << 4) | low);
  }
  return RLC_OK;
}

int bench_parse_options(int argc, char **argv, bench_options_t *options) {
  int i;
  if (options == NULL) {
    return RLC_ERR;
  }
  options->mode = BENCH_MODE_ORIGINAL_ITEMWISE;
  options->count = 1;
  options->pair_id = 0;
  options->port = 19081;
  options->io_timeout_ms = 120000;
  options->completion_ack_timeout_ms = 5000;
  options->completion_retries = 3;
  options->completion_retry_delay_ms = 1000;
  options->execution_id = 1;
  options->context_participants = 0;
  options->context_epoch = 1;
  options->context_expiry = 3600;
  options->context_arc_index = 0;
  memset(options->context_seed, 0, sizeof(options->context_seed));
  options->context_seed_set = 0;
  memset(options->host_statements, 0, sizeof(options->host_statements));
  options->host_output_fd = -1;
  options->host_export_deadline_ns = 0;
  options->host_key_fd = -1;
  options->host_address_keys_fd = -1;
  options->host_client_keys_fd = -1;
  options->host_server_keys_fd = -1;
  options->host_admitted_keys = NULL;
  memset(options->host_peer_key,0,sizeof(options->host_peer_key));
  options->inject_bad_preparation_proof = 0;
  options->inject_bad_open = 0;
  options->inject_bad_server_partial = 0;
  options->inject_bad_final = 0;
  options->use_tcp = 0;
  options->use_gateway = 0;
  options->pool_worker = 0;
  options->pool_worker_index = 0;
  memset(options->gateway_backend, 0, sizeof(options->gateway_backend));
  memset(options->curve_public_key_file, 0,
         sizeof(options->curve_public_key_file));
  memset(options->curve_secret_key_file, 0,
         sizeof(options->curve_secret_key_file));
  memset(options->curve_server_key_file, 0,
         sizeof(options->curve_server_key_file));
  memset(options->curve_allowed_client_key_file, 0,
         sizeof(options->curve_allowed_client_key_file));
  memcpy(options->zap_domain, "PARASWAP-OASIS-PRESWAP-v1",
         sizeof("PARASWAP-OASIS-PRESWAP-v1"));
  memcpy(options->host, "127.0.0.1", sizeof("127.0.0.1"));
  memcpy(options->bind, "127.0.0.1", sizeof("127.0.0.1"));

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      i++;
      if (strcmp(argv[i], "reference-itemwise") == 0) {
        options->mode = BENCH_MODE_ORIGINAL_ITEMWISE;
      } else if (strcmp(argv[i], "phase-coalesced-itemwise") == 0) {
        options->mode = BENCH_MODE_PHASE_COALESCED_ITEMWISE;
      } else if (
          strcmp(argv[i], "batch-joint-presigning-itemwise") == 0) {
        options->mode = BENCH_MODE_BJP_ITEMWISE;
      } else if (
          strcmp(argv[i], "phase-coalesced-batch-verification") == 0) {
        options->mode = BENCH_MODE_PHASE_COALESCED_MSM;
      } else if (strcmp(
                     argv[i],
                     "batch-joint-presigning-batch-verification") == 0) {
        options->mode = BENCH_MODE_BJP_MSM;
      } else {
        fprintf(stderr, "unsupported mode: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->count) != RLC_OK ||
          options->count == 0 || options->count > BENCH_MAX_ITEMS) {
        fprintf(stderr, "invalid count: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--pair-id") == 0 && i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->pair_id) != RLC_OK) {
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->port) != RLC_OK || options->port > 65535) {
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
      i++;
      if (strcmp(argv[i], "ipc") == 0) {
        options->use_tcp = 0;
      } else if (strcmp(argv[i], "tcp") == 0) {
        options->use_tcp = 1;
      } else {
        fprintf(stderr, "unsupported transport: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
      i++;
      if (copy_endpoint_host(options->host, argv[i]) != RLC_OK) {
        fprintf(stderr, "invalid host\n");
        return RLC_ERR;
      }
      options->use_tcp = 1;
    } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
      i++;
      if (copy_endpoint_host(options->bind, argv[i]) != RLC_OK) {
        fprintf(stderr, "invalid bind address\n");
        return RLC_ERR;
      }
      options->use_tcp = 1;
    } else if (strcmp(argv[i], "--io-timeout-ms") == 0 && i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->io_timeout_ms) != RLC_OK ||
          options->io_timeout_ms == 0 || options->io_timeout_ms > INT32_MAX) {
        fprintf(stderr, "invalid I/O timeout: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--completion-ack-timeout-ms") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->completion_ack_timeout_ms) != RLC_OK ||
          options->completion_ack_timeout_ms == 0 ||
          options->completion_ack_timeout_ms > INT32_MAX) {
        fprintf(stderr, "invalid completion acknowledgement timeout: %s\n",
                argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--completion-retries") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->completion_retries) != RLC_OK ||
          options->completion_retries > 100) {
        fprintf(stderr, "invalid completion retry count: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--completion-retry-delay-ms") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->completion_retry_delay_ms) != RLC_OK ||
          options->completion_retry_delay_ms > INT32_MAX) {
        fprintf(stderr, "invalid completion retry delay: %s\n", argv[i]);
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--gateway-backend") == 0 && i + 1 < argc) {
      i++;
      if (copy_ipc_endpoint(options->gateway_backend,
                            sizeof(options->gateway_backend), argv[i]) != RLC_OK) {
        fprintf(stderr, "invalid gateway backend; expected ipc:// endpoint\n");
        return RLC_ERR;
      }
      options->use_gateway = 1;
    } else if (strcmp(argv[i], "--pool-worker-index") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->pool_worker_index) != RLC_OK) {
        return RLC_ERR;
      }
      options->pool_worker = 1;
    } else if (strcmp(argv[i], "--curve-public-key") == 0 && i + 1 < argc) {
      i++;
      if (copy_auth_value(options->curve_public_key_file,
                          sizeof(options->curve_public_key_file),
                          argv[i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--curve-secret-key") == 0 && i + 1 < argc) {
      i++;
      if (copy_auth_value(options->curve_secret_key_file,
                          sizeof(options->curve_secret_key_file),
                          argv[i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--curve-server-key") == 0 && i + 1 < argc) {
      i++;
      if (copy_auth_value(options->curve_server_key_file,
                          sizeof(options->curve_server_key_file),
                          argv[i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--curve-allowed-client-key") == 0 &&
               i + 1 < argc) {
      i++;
      if (copy_auth_value(options->curve_allowed_client_key_file,
                          sizeof(options->curve_allowed_client_key_file),
                          argv[i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--zap-domain") == 0 && i + 1 < argc) {
      i++;
      if (copy_auth_value(options->zap_domain, sizeof(options->zap_domain),
                          argv[i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--inject-bad-preparation-proof") == 0) {
      options->inject_bad_preparation_proof = 1;
    } else if (strcmp(argv[i], "--inject-bad-open") == 0) {
      options->inject_bad_open = 1;
    } else if (strcmp(argv[i], "--inject-bad-server-partial") == 0) {
      options->inject_bad_server_partial = 1;
    } else if (strcmp(argv[i], "--inject-bad-final") == 0) {
      options->inject_bad_final = 1;
    } else if (strcmp(argv[i], "--execution-id") == 0 && i + 1 < argc) {
      i++;
      if (parse_u64(argv[i], &options->execution_id) != RLC_OK) {
        return RLC_ERR;
      }
    } else if (strcmp(argv[i], "--context-participants") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_uint(argv[i], &options->context_participants) != RLC_OK ||
          options->context_participants < 2) return RLC_ERR;
    } else if (strcmp(argv[i], "--context-epoch") == 0 && i + 1 < argc) {
      i++;
      if (parse_u64(argv[i], &options->context_epoch) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--context-expiry") == 0 && i + 1 < argc) {
      i++;
      if (parse_u64(argv[i], &options->context_expiry) != RLC_OK ||
          options->context_expiry == 0) return RLC_ERR;
    } else if (strcmp(argv[i], "--context-arc-index") == 0 &&
               i + 1 < argc) {
      i++;
      if (parse_u64(argv[i], &options->context_arc_index) != RLC_OK) {
        return RLC_ERR;
      }
    } else if ((!strcmp(argv[i],"--host-address-keys-fd") ||
                !strcmp(argv[i],"--host-client-keys-fd") ||
                !strcmp(argv[i],"--host-server-keys-fd")) && i+1<argc) {
      int *destination=!strcmp(argv[i],"--host-address-keys-fd") ? &options->host_address_keys_fd :
          (!strcmp(argv[i],"--host-client-keys-fd") ? &options->host_client_keys_fd : &options->host_server_keys_fd);
      unsigned fd;
      if (parse_uint(argv[++i],&fd)!=RLC_OK || fd<3 || fd>1048575) return RLC_ERR;
      *destination=(int)fd;
    } else if (strcmp(argv[i], "--host-key-fd") == 0 && i + 1 < argc) {
      unsigned fd;
      if (parse_uint(argv[++i], &fd) != RLC_OK || fd < 3 || fd > 1048575)
        return RLC_ERR;
      options->host_key_fd = (int) fd;
    } else if (!strcmp(argv[i],"--host-export-deadline-ns") && i+1<argc) {
      if (parse_u64(argv[++i],&options->host_export_deadline_ns)!=RLC_OK ||
          options->host_export_deadline_ns==0 || options->host_export_deadline_ns>INT64_MAX)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--host-output-fd") == 0 && i + 1 < argc) {
      unsigned fd;
      if (parse_uint(argv[++i], &fd) != RLC_OK || fd < 3 || fd > 1048575)
        return RLC_ERR;
      options->host_output_fd = (int) fd;
    } else if ((strcmp(argv[i], "--host-statements") == 0 ||
                strcmp(argv[i], "--host-peer-key") == 0) && i + 1 < argc) {
      char *destination = !strcmp(argv[i],"--host-peer-key")
          ? options->host_peer_key : options->host_statements;
      i++;
      if (strlen(argv[i]) == 0 || strlen(argv[i]) >= BENCH_AUTH_PATH_BYTES)
        return RLC_ERR;
      strcpy(destination, argv[i]);
    } else if (strcmp(argv[i], "--context-seed-hex") == 0 && i + 1 < argc) {
      i++;
      if (parse_hex_digest(argv[i], options->context_seed) != RLC_OK) {
        fprintf(stderr, "invalid context seed; expected 64 hex characters\n");
        return RLC_ERR;
      }
      options->context_seed_set = 1;
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return RLC_ERR;
    }
  }
  if (options->context_participants == 0) {
    options->context_participants = (options->count + 1) / 2;
  }
  if (options->count != 2 * options->context_participants - 1 ||
      !options->context_seed_set) {
    fprintf(stderr,
            "count must equal 2*n-1 and --context-seed-hex is required\n");
    return RLC_ERR;
  }
  if (options->context_arc_index == 0) {
    options->context_arc_index = (uint64_t) options->pair_id + 1;
  }
  return RLC_OK;
}

static void write_u32(uint8_t *buffer, uint32_t value) {
  value = htonl(value);
  memcpy(buffer, &value, sizeof(value));
}

static uint32_t read_u32(const uint8_t *buffer) {
  uint32_t value;
  memcpy(&value, buffer, sizeof(value));
  return ntohl(value);
}

static void write_u64(uint8_t *buffer, uint64_t value) {
  write_u32(buffer, (uint32_t) (value >> 32));
  write_u32(buffer + 4, (uint32_t) value);
}

static uint64_t read_u64(const uint8_t *buffer) {
  return ((uint64_t) read_u32(buffer) << 32) | read_u32(buffer + 4);
}

void bench_write_header(uint8_t *buffer, bench_msg_type_t type, uint32_t count,
                        uint32_t pair_id, uint32_t first_ordinal,
                        uint64_t execution_id) {
  uint8_t sid[BENCH_DIGEST_BYTES] = {0};
  bench_write_header_sid(buffer, type, count, pair_id, first_ordinal,
                         execution_id, sid);
}

void bench_write_header_sid(uint8_t *buffer, bench_msg_type_t type,
                            uint32_t count, uint32_t pair_id,
                            uint32_t first_ordinal, uint64_t execution_id,
                            const uint8_t sid[BENCH_DIGEST_BYTES]) {
  write_u32(buffer, BENCH_MAGIC);
  write_u32(buffer + 4, BENCH_VERSION);
  write_u32(buffer + 8, (uint32_t) type);
  write_u32(buffer + 12, count);
  write_u32(buffer + 16, pair_id);
  write_u32(buffer + 20, first_ordinal);
  write_u64(buffer + 24, execution_id);
  memcpy(buffer + 32, sid, BENCH_DIGEST_BYTES);
}

int bench_read_header(const uint8_t *buffer, size_t length,
                      bench_header_t *header) {
  if (buffer == NULL || header == NULL || length < BENCH_HEADER_SIZE) {
    return RLC_ERR;
  }
  header->magic = read_u32(buffer);
  header->version = read_u32(buffer + 4);
  header->type = read_u32(buffer + 8);
  header->count = read_u32(buffer + 12);
  header->pair_id = read_u32(buffer + 16);
  header->first_ordinal = read_u32(buffer + 20);
  header->execution_id = read_u64(buffer + 24);
  memcpy(header->sid, buffer + 32, BENCH_DIGEST_BYTES);
  return header->magic == BENCH_MAGIC && header->version == BENCH_VERSION
             ? RLC_OK
             : RLC_ERR;
}

int bench_make_client_endpoint(char *buffer, size_t buffer_size,
                               const bench_options_t *options) {
  int written;
  if (buffer == NULL || options == NULL) return RLC_ERR;
  if (options->use_tcp) {
    written = snprintf(buffer, buffer_size, "tcp://%s:%u",
                       options->host, options->port);
  } else {
    written = snprintf(buffer, buffer_size,
                       "ipc:///tmp/oasis-preswap-%u.sock", options->port);
  }
  return written > 0 && (size_t) written < buffer_size ? RLC_OK : RLC_ERR;
}

int bench_make_server_endpoint(char *buffer, size_t buffer_size,
                               const bench_options_t *options) {
  int written;
  if (buffer == NULL || options == NULL) return RLC_ERR;
  if (!options->use_tcp) {
    return bench_make_client_endpoint(buffer, buffer_size, options);
  }
  written = snprintf(buffer, buffer_size, "tcp://%s:%u",
                     options->bind, options->port);
  return written > 0 && (size_t) written < buffer_size ? RLC_OK : RLC_ERR;
}

void bench_cleanup_endpoint(const char *endpoint) {
  static const char prefix[] = "ipc://";
  if (endpoint != NULL && strncmp(endpoint, prefix, sizeof(prefix) - 1) == 0) {
    unlink(endpoint + sizeof(prefix) - 1);
  }
}

int bench_send_frame(void *socket, const uint8_t *buffer, size_t length) {
  zmq_msg_t message;
  int rc;
  if (socket == NULL || buffer == NULL || zmq_msg_init_size(&message, length) != 0) {
    return RLC_ERR;
  }
  memcpy(zmq_msg_data(&message), buffer, length);
  rc = zmq_msg_send(&message, socket, 0);
  zmq_msg_close(&message);
  return rc == (int) length ? RLC_OK : RLC_ERR;
}

int bench_recv_frame(void *socket, uint8_t **buffer, size_t *length) {
  zmq_msg_t message;
  int rc;
  if (socket == NULL || buffer == NULL || length == NULL ||
      zmq_msg_init(&message) != 0) {
    return RLC_ERR;
  }
  rc = zmq_msg_recv(&message, socket, 0);
  if (rc < 0) {
    zmq_msg_close(&message);
    return RLC_ERR;
  }
  *length = (size_t) rc;
  *buffer = malloc(*length);
  if (*buffer == NULL) {
    zmq_msg_close(&message);
    return RLC_ERR;
  }
  memcpy(*buffer, zmq_msg_data(&message), *length);
  zmq_msg_close(&message);
  return RLC_OK;
}

void bench_item_digest(bench_mode_t mode, uint32_t pair_id, uint32_t ordinal,
                       uint32_t total_items, uint64_t execution_id,
                       uint8_t out[BENCH_DIGEST_BYTES]) {
  static const char domain[] = "PARASWAP-OASIS-ITEM-v2";
  uint8_t input[sizeof(domain) - 1 + 24];
  memcpy(input, domain, sizeof(domain) - 1);
  write_u32(input + sizeof(domain) - 1, (uint32_t) mode);
  write_u32(input + sizeof(domain) - 1 + 4, pair_id);
  write_u32(input + sizeof(domain) - 1 + 8, ordinal);
  write_u32(input + sizeof(domain) - 1 + 12, total_items);
  write_u64(input + sizeof(domain) - 1 + 16, execution_id);
  md_map(out, input, sizeof(input));
}

void bench_item_session_digest(uint32_t pair_id, uint32_t ordinal,
                               uint32_t total_items, uint64_t execution_id,
                               uint8_t out[BENCH_ITEM_SESSION_BYTES]) {
  static const char domain[] = "PARASWAP-OASIS-ITEM-SESSION-v1";
  uint8_t input[sizeof(domain) - 1 + 20];
  memcpy(input, domain, sizeof(domain) - 1);
  write_u32(input + sizeof(domain) - 1, pair_id);
  write_u32(input + sizeof(domain) - 1 + 4, ordinal);
  write_u32(input + sizeof(domain) - 1 + 8, total_items);
  write_u64(input + sizeof(domain) - 1 + 12, execution_id);
  md_map(out, input, sizeof(input));
}

static int bench_item_key_tweak(bn_t tweak, const char *key_domain,
                                uint32_t pair_id, uint32_t ordinal,
                                uint32_t total_items, const bn_t order) {
  static const char prefix[] = "PARASWAP-OASIS-ITEM-KEY-v1";
  size_t domain_length;
  size_t input_length;
  uint8_t hash[RLC_MD_LEN];
  uint8_t *input;
  uint8_t *cursor;
  if (key_domain == NULL || key_domain[0] == '\0') return RLC_ERR;
  domain_length = strlen(key_domain);
  if (domain_length > UINT32_MAX) return RLC_ERR;
  input_length = sizeof(prefix) - 1 + 4 + domain_length + 12;
  input = malloc(input_length);
  if (input == NULL) return RLC_ERR;
  cursor = input;
  memcpy(cursor, prefix, sizeof(prefix) - 1);
  cursor += sizeof(prefix) - 1;
  write_u32(cursor, (uint32_t) domain_length);
  cursor += 4;
  memcpy(cursor, key_domain, domain_length);
  cursor += domain_length;
  write_u32(cursor, pair_id);
  write_u32(cursor + 4, ordinal);
  write_u32(cursor + 8, total_items);
  md_map(hash, input, input_length);
  free(input);
  bn_read_bin(tweak, hash, RLC_MD_LEN);
  bn_mod(tweak, tweak, order);
  if (bn_is_zero(tweak)) bn_set_dig(tweak, 1);
  return RLC_OK;
}

int bench_derive_item_secret(bn_t derived, const bn_t base_secret,
                             const char *key_domain, uint32_t pair_id,
                             uint32_t ordinal, uint32_t total_items) {
  bn_t order;
  bn_t tweak;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(tweak);
  RLC_TRY {
    bn_new(order);
    bn_new(tweak);
    ec_curve_get_ord(order);
    if (bench_item_key_tweak(tweak, key_domain, pair_id, ordinal,
                             total_items, order) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    bn_add(derived, base_secret, tweak);
    bn_mod(derived, derived, order);
    if (bn_is_zero(derived)) bn_set_dig(derived, 1);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(tweak);
  }
  return status;
}

int bench_derive_item_public(ec_t derived, const ec_t base_public,
                             const char *key_domain, uint32_t pair_id,
                             uint32_t ordinal, uint32_t total_items) {
  bn_t order;
  bn_t tweak;
  ec_t offset;
  int status = RLC_ERR;
  bn_null(order);
  bn_null(tweak);
  ec_null(offset);
  RLC_TRY {
    bn_new(order);
    bn_new(tweak);
    ec_new(offset);
    ec_curve_get_ord(order);
    if (ec_is_infty(base_public) || !ec_on_curve(base_public) ||
        bench_item_key_tweak(tweak, key_domain, pair_id, ordinal,
                             total_items, order) != RLC_OK) {
      RLC_THROW(ERR_NO_VALID);
    }
    ec_mul_gen(offset, tweak);
    ec_add(derived, base_public, offset);
    ec_norm(derived, derived);
    if (ec_is_infty(derived)) ec_curve_get_gen(derived);
    status = RLC_OK;
  } RLC_CATCH_ANY {
    status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(order);
    bn_free(tweak);
    ec_free(offset);
  }
  return status;
}

void bench_commitment_digest(const uint8_t *open_payload, size_t payload_length,
                             uint8_t out[BENCH_DIGEST_BYTES]) {
  static const char domain[] = "PARASWAP-OASIS-SERVER-COMMIT-v1";
  uint8_t *input = malloc(sizeof(domain) - 1 + payload_length);
  if (input == NULL) {
    memset(out, 0, BENCH_DIGEST_BYTES);
    return;
  }
  memcpy(input, domain, sizeof(domain) - 1);
  memcpy(input + sizeof(domain) - 1, open_payload, payload_length);
  md_map(out, input, sizeof(domain) - 1 + payload_length);
  free(input);
}

int bench_independent_completion_digest(
    const uint8_t *ordered_commitments, unsigned count, uint32_t pair_id,
    uint64_t execution_id, uint8_t out[BENCH_DIGEST_BYTES]) {
  static const char domain[] = "PARASWAP-OASIS-INDEPENDENT-DONE-v1";
  const size_t prefix_length = sizeof(domain) - 1 + 16;
  size_t commitments_length;
  uint8_t *input;
  if (ordered_commitments == NULL || out == NULL || count == 0 ||
      count > BENCH_MAX_ITEMS) {
    return RLC_ERR;
  }
  commitments_length = (size_t) count * BENCH_DIGEST_BYTES;
  input = malloc(prefix_length + commitments_length);
  if (input == NULL) return RLC_ERR;
  memcpy(input, domain, sizeof(domain) - 1);
  write_u32(input + sizeof(domain) - 1, pair_id);
  write_u32(input + sizeof(domain) - 1 + 4, count);
  write_u64(input + sizeof(domain) - 1 + 8, execution_id);
  memcpy(input + prefix_length, ordered_commitments, commitments_length);
  md_map(out, input, prefix_length + commitments_length);
  free(input);
  return RLC_OK;
}

int bench_digest_equal(const uint8_t left[BENCH_DIGEST_BYTES],
                       const uint8_t right[BENCH_DIGEST_BYTES]) {
  unsigned i;
  uint8_t difference = 0;
  for (i = 0; i < BENCH_DIGEST_BYTES; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}

void bench_print_result(const bench_result_t *result) {
  long long average_ns;
  if (result == NULL || result->item_count == 0) {
    return;
  }
  average_ns = result->total_time_ns / (long long) result->item_count;
  printf("RESULT\t%s\t%u\t%u\t%lld\t%lld\t%zu\t%zu\t%u\t%u\n",
         bench_mode_name(result->mode), result->pair_id, result->item_count,
         result->total_time_ns, average_ns, result->bytes_sent,
         result->bytes_received, result->sent_frames, result->received_frames);
  printf("CRYPTO_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%lld\t%lld\n",
         bench_mode_name(result->mode), result->pair_id, result->item_count,
         result->total_crypto_ns, result->request_sign_ns,
         result->response_preverify_ns, result->final_sign_ns);
  printf("VERIFIER_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%u\t%u\t%u\n",
         bench_mode_name(result->mode), result->pair_id, result->item_count,
         result->verifier_challenge_ns, result->verifier_msm_ns,
         result->verifier_equations, result->verifier_msm_calls,
         result->verifier_fallbacks);
  printf("RESOURCE_RESULT\t%s\t%u\t%u\t%lld\t%lld\t%lld\t%ld\t%ld\t%ld\t%lld\t%lld\t%u\t%u\n",
         bench_mode_name(result->mode), result->pair_id, result->item_count,
         result->setup_ns, result->user_cpu_ns, result->system_cpu_ns,
         result->max_rss_kb, result->voluntary_context_switches,
         result->involuntary_context_switches, result->scheduler_wait_ns,
         result->scheduler_slices, result->send_calls, result->receive_calls);
}
