#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "zmq.h"
#include "completion_journal.h"
#include "preswap_protocol.h"
#include "transport_auth.h"

#define MAX_ROUTING_ID_BYTES 255u
#define ASSIGNMENT_BYTES (BENCH_HEADER_SIZE + 64u)
#define CURVE_TRANSPORT_OVERHEAD_ALLOWANCE 1024u

typedef struct gateway_frame {
  uint8_t *data;
  size_t length;
  struct gateway_frame *next;
} gateway_frame_t;

typedef struct {
  unsigned pair_id;
  uint64_t execution_id;
  uint64_t context_arc_index;
  uint8_t context_seed[BENCH_CONTEXT_SEED_BYTES];
  uint8_t client_id[MAX_ROUTING_ID_BYTES];
  size_t client_id_length;
  gateway_frame_t *pending_head;
  gateway_frame_t *pending_tail;
  unsigned pending_count;
  long long queued_at_ns;
  int client_seen;
  int queued;
  int assigned;
  int terminal;
  unsigned worker_index;
} gateway_route_t;

typedef struct {
  uint8_t identity[MAX_ROUTING_ID_BYTES];
  size_t identity_length;
  unsigned route_index;
  int registered;
  int busy;
} gateway_worker_t;

typedef struct {
  char bind[BENCH_ENDPOINT_HOST_BYTES];
  unsigned port;
  unsigned expected_sessions;
  unsigned worker_count;
  unsigned max_queue;
  unsigned io_timeout_ms;
  bench_mode_t mode;
  unsigned count;
  unsigned context_participants;
  uint64_t context_epoch;
  uint64_t context_expiry;
  char backend[BENCH_ENDPOINT_BYTES];
  char session_manifest[BENCH_AUTH_PATH_BYTES];
  char completion_dir[BENCH_AUTH_PATH_BYTES];
  unsigned completion_grace_ms;
  int test_drop_first_done_after_persist;
  bench_options_t auth;
} gateway_options_t;

typedef struct {
  unsigned frontend_received;
  unsigned frontend_sent;
  unsigned backend_received;
  unsigned backend_sent;
  size_t bytes_from_clients;
  size_t bytes_to_clients;
  unsigned assignments;
  unsigned queued_sessions;
  unsigned rejected_sessions;
  unsigned peak_busy_workers;
  unsigned peak_queue_depth;
  unsigned internal_control_frames;
  long long total_queue_wait_ns;
  long long max_queue_wait_ns;
  unsigned completion_records_written;
  unsigned completion_replay_requests;
  unsigned completion_replays;
  unsigned test_dropped_done_frames;
} gateway_metrics_t;

static int copy_value(char *out, size_t out_size, const char *value) {
  size_t length;
  if (out == NULL || out_size == 0 || value == NULL || value[0] == '\0') {
    return RLC_ERR;
  }
  length = strlen(value);
  if (length >= out_size) return RLC_ERR;
  memcpy(out, value, length + 1);
  return RLC_OK;
}

static int parse_unsigned(const char *value, unsigned *out) {
  char *end = NULL;
  unsigned long parsed;
  if (value == NULL || out == NULL) return RLC_ERR;
  errno = 0;
  parsed = strtoul(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX) {
    return RLC_ERR;
  }
  *out = (unsigned) parsed;
  return RLC_OK;
}

static int parse_u64(const char *value, uint64_t *out) {
  char *end = NULL;
  unsigned long long parsed;
  if (value == NULL || out == NULL) return RLC_ERR;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0') return RLC_ERR;
  *out = (uint64_t) parsed;
  return RLC_OK;
}

static int parse_mode(const char *value, bench_mode_t *mode) {
  if (strcmp(value, "reference-itemwise") == 0) {
    *mode = BENCH_MODE_ORIGINAL_ITEMWISE;
  } else if (strcmp(value, "phase-coalesced-itemwise") == 0) {
    *mode = BENCH_MODE_PHASE_COALESCED_ITEMWISE;
  } else if (strcmp(value, "batch-joint-presigning-itemwise") == 0) {
    *mode = BENCH_MODE_BJP_ITEMWISE;
  } else if (strcmp(value, "phase-coalesced-batch-verification") == 0) {
    *mode = BENCH_MODE_PHASE_COALESCED_MSM;
  } else if (strcmp(value,
                    "batch-joint-presigning-batch-verification") == 0) {
    *mode = BENCH_MODE_BJP_MSM;
  } else {
    return RLC_ERR;
  }
  return RLC_OK;
}

static int parse_options(int argc, char **argv, gateway_options_t *options) {
  int i;
  if (options == NULL) return RLC_ERR;
  memset(options, 0, sizeof(*options));
  memcpy(options->bind, "0.0.0.0", sizeof("0.0.0.0"));
  options->port = 9000;
  options->io_timeout_ms = 120000;
  options->context_epoch = 1;
  options->context_expiry = 3600;
  memcpy(options->auth.zap_domain, "PARASWAP-OASIS-PRESWAP-v1",
         sizeof("PARASWAP-OASIS-PRESWAP-v1"));
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
      if (copy_value(options->bind, sizeof(options->bind), argv[++i]) != RLC_OK)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->port) != RLC_OK ||
          options->port < 1024 || options->port > 65535) return RLC_ERR;
    } else if (strcmp(argv[i], "--expected-sessions") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->expected_sessions) != RLC_OK ||
          options->expected_sessions == 0 ||
          options->expected_sessions > BENCH_MAX_ITEMS) return RLC_ERR;
    } else if (strcmp(argv[i], "--worker-count") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->worker_count) != RLC_OK ||
          options->worker_count == 0) return RLC_ERR;
    } else if (strcmp(argv[i], "--max-queue") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->max_queue) != RLC_OK)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      if (parse_mode(argv[++i], &options->mode) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->count) != RLC_OK ||
          options->count == 0 || options->count > BENCH_MAX_ITEMS)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--context-participants") == 0 &&
               i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->context_participants) != RLC_OK ||
          options->context_participants < 2) return RLC_ERR;
    } else if (strcmp(argv[i], "--context-epoch") == 0 && i + 1 < argc) {
      if (parse_u64(argv[++i], &options->context_epoch) != RLC_OK)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--context-expiry") == 0 && i + 1 < argc) {
      if (parse_u64(argv[++i], &options->context_expiry) != RLC_OK ||
          options->context_expiry == 0) return RLC_ERR;
    } else if (strcmp(argv[i], "--session-manifest") == 0 && i + 1 < argc) {
      if (copy_value(options->session_manifest,
                     sizeof(options->session_manifest), argv[++i]) != RLC_OK)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--completion-dir") == 0 && i + 1 < argc) {
      if (copy_value(options->completion_dir,
                     sizeof(options->completion_dir), argv[++i]) != RLC_OK)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--completion-grace-ms") == 0 &&
               i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->completion_grace_ms) != RLC_OK ||
          options->completion_grace_ms > INT32_MAX) return RLC_ERR;
    } else if (strcmp(argv[i],
                      "--test-drop-first-done-after-persist") == 0) {
      options->test_drop_first_done_after_persist = 1;
    } else if (strcmp(argv[i], "--io-timeout-ms") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &options->io_timeout_ms) != RLC_OK ||
          options->io_timeout_ms == 0 || options->io_timeout_ms > INT32_MAX)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
      if (copy_value(options->backend, sizeof(options->backend), argv[++i]) !=
              RLC_OK ||
          strncmp(options->backend, "ipc://", sizeof("ipc://") - 1) != 0)
        return RLC_ERR;
    } else if (strcmp(argv[i], "--curve-secret-key") == 0 && i + 1 < argc) {
      if (copy_value(options->auth.curve_secret_key_file,
                     sizeof(options->auth.curve_secret_key_file),
                     argv[++i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--curve-allowed-client-key") == 0 &&
               i + 1 < argc) {
      if (copy_value(options->auth.curve_allowed_client_key_file,
                     sizeof(options->auth.curve_allowed_client_key_file),
                     argv[++i]) != RLC_OK) return RLC_ERR;
    } else if (strcmp(argv[i], "--zap-domain") == 0 && i + 1 < argc) {
      if (copy_value(options->auth.zap_domain, sizeof(options->auth.zap_domain),
                     argv[++i]) != RLC_OK) return RLC_ERR;
    } else {
      return RLC_ERR;
    }
  }
  if (options->max_queue == 0) options->max_queue = options->expected_sessions;
  return options->expected_sessions != 0 && options->worker_count != 0 &&
                 options->worker_count <= options->expected_sessions &&
                 options->count == 2 * options->context_participants - 1 &&
                 options->backend[0] != '\0' &&
                 options->session_manifest[0] != '\0' &&
                 options->completion_dir[0] != '\0' &&
                 options->auth.curve_secret_key_file[0] != '\0' &&
                 options->auth.curve_allowed_client_key_file[0] != '\0'
             ? RLC_OK
             : RLC_ERR;
}

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_seed(const char *hex, uint8_t out[BENCH_CONTEXT_SEED_BYTES]) {
  unsigned i;
  if (strlen(hex) != 2 * BENCH_CONTEXT_SEED_BYTES) return RLC_ERR;
  for (i = 0; i < BENCH_CONTEXT_SEED_BYTES; i++) {
    int high = hex_value(hex[2 * i]);
    int low = hex_value(hex[2 * i + 1]);
    if (high < 0 || low < 0) return RLC_ERR;
    out[i] = (uint8_t) ((high << 4) | low);
  }
  return RLC_OK;
}

static int load_manifest(const gateway_options_t *options,
                         gateway_route_t *routes) {
  FILE *file = fopen(options->session_manifest, "r");
  unsigned loaded = 0;
  char line[256];
  if (file == NULL) return RLC_ERR;
  while (fgets(line, sizeof(line), file) != NULL) {
    unsigned pair_id;
    unsigned long long execution_id;
    unsigned long long arc_index;
    char seed_hex[2 * BENCH_CONTEXT_SEED_BYTES + 1];
    gateway_route_t *route;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (sscanf(line, "%u %llu %llu %64s", &pair_id, &execution_id,
               &arc_index, seed_hex) != 4 ||
        pair_id >= options->expected_sessions || routes[pair_id].execution_id ||
        execution_id == 0 || arc_index == 0) {
      fclose(file);
      return RLC_ERR;
    }
    route = &routes[pair_id];
    route->pair_id = pair_id;
    route->execution_id = (uint64_t) execution_id;
    route->context_arc_index = (uint64_t) arc_index;
    if (parse_seed(seed_hex, route->context_seed) != RLC_OK) {
      fclose(file);
      return RLC_ERR;
    }
    loaded++;
  }
  fclose(file);
  return loaded == options->expected_sessions ? RLC_OK : RLC_ERR;
}

static int recv_routed(void *socket, uint8_t identity[MAX_ROUTING_ID_BYTES],
                       size_t *identity_length, uint8_t **payload,
                       size_t *payload_length) {
  zmq_msg_t part;
  int more = 0;
  size_t more_length = sizeof(more);
  int received;
  *payload = NULL;
  *payload_length = 0;
  if (zmq_msg_init(&part) != 0) return RLC_ERR;
  received = zmq_msg_recv(&part, socket, 0);
  if (received <= 0 || (size_t) received > MAX_ROUTING_ID_BYTES ||
      zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_length) != 0 || !more) {
    zmq_msg_close(&part);
    return RLC_ERR;
  }
  *identity_length = (size_t) received;
  memcpy(identity, zmq_msg_data(&part), *identity_length);
  zmq_msg_close(&part);
  if (zmq_msg_init(&part) != 0) return RLC_ERR;
  received = zmq_msg_recv(&part, socket, 0);
  if (received < 0 ||
      zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_length) != 0 || more) {
    zmq_msg_close(&part);
    return RLC_ERR;
  }
  *payload_length = (size_t) received;
  *payload = malloc(*payload_length == 0 ? 1 : *payload_length);
  if (*payload == NULL) {
    zmq_msg_close(&part);
    return RLC_ERR;
  }
  if (*payload_length != 0)
    memcpy(*payload, zmq_msg_data(&part), *payload_length);
  zmq_msg_close(&part);
  return RLC_OK;
}

static int send_routed(void *socket, const uint8_t *identity,
                       size_t identity_length, const uint8_t *payload,
                       size_t payload_length) {
  return socket != NULL && identity != NULL && identity_length != 0 &&
                 payload != NULL &&
                 zmq_send(socket, identity, identity_length, ZMQ_SNDMORE) ==
                     (int) identity_length &&
                 zmq_send(socket, payload, payload_length, 0) ==
                     (int) payload_length
             ? RLC_OK
             : RLC_ERR;
}

static int identity_equal(const uint8_t *left, size_t left_length,
                          const uint8_t *right, size_t right_length) {
  return left_length == right_length &&
         memcmp(left, right, left_length) == 0;
}

static int client_identity_available(const gateway_route_t *routes,
                                     unsigned count, unsigned pair_id,
                                     const uint8_t *identity,
                                     size_t identity_length) {
  unsigned i;
  for (i = 0; i < count; i++) {
    if (i != pair_id && routes[i].client_seen &&
        identity_equal(routes[i].client_id, routes[i].client_id_length,
                       identity, identity_length)) return 0;
  }
  return 1;
}

static void write_u32_be(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t) (value >> 24);
  out[1] = (uint8_t) (value >> 16);
  out[2] = (uint8_t) (value >> 8);
  out[3] = (uint8_t) value;
}

static void write_u64_be(uint8_t out[8], uint64_t value) {
  write_u32_be(out, (uint32_t) (value >> 32));
  write_u32_be(out + 4, (uint32_t) value);
}

static uint32_t read_u32_be(const uint8_t in[4]) {
  return ((uint32_t) in[0] << 24) | ((uint32_t) in[1] << 16) |
         ((uint32_t) in[2] << 8) | (uint32_t) in[3];
}

static int status_is_terminal(const uint8_t *payload, size_t length) {
  const size_t offset = BENCH_HEADER_SIZE + 2 * BENCH_SALT_BYTES;
  return length >= offset + 4 && read_u32_be(payload + offset) != 0;
}

static int64_t maximum_client_frame_bytes(const gateway_options_t *options) {
  const size_t item_sid = bench_mode_has_item_sessions(options->mode)
                              ? BENCH_ITEM_SESSION_BYTES
                              : 0;
  const size_t init = BENCH_HEADER_SIZE + 2 * BENCH_DIGEST_BYTES +
                      BENCH_KEY_OWNERSHIP_PROOF_BYTES +
                      (size_t) options->count *
                          (item_sid + BENCH_DIGEST_BYTES);
  const size_t nonce = BENCH_HEADER_SIZE + (size_t) options->count *
                                           (item_sid + BENCH_POINT_BYTES);
  const size_t final = BENCH_HEADER_SIZE + (size_t) options->count *
                                           (item_sid + BENCH_SCALAR_BYTES);
  size_t maximum = init > nonce ? init : nonce;
  if (final > maximum) maximum = final;
  return (int64_t) (maximum + CURVE_TRANSPORT_OVERHEAD_ALLOWANCE);
}

static size_t expected_init_frame_bytes(const gateway_options_t *options,
                                        unsigned count, unsigned first) {
  const size_t item_sid = bench_mode_has_item_sessions(options->mode)
                              ? BENCH_ITEM_SESSION_BYTES
                              : 0;
  return BENCH_HEADER_SIZE + 2 * BENCH_DIGEST_BYTES +
         (first == 0 ? BENCH_KEY_OWNERSHIP_PROOF_BYTES : 0) +
         (size_t) count * (item_sid + BENCH_DIGEST_BYTES);
}

static int make_frontend(char out[BENCH_ENDPOINT_BYTES],
                         const gateway_options_t *options) {
  int written = snprintf(out, BENCH_ENDPOINT_BYTES, "tcp://%s:%u",
                         options->bind, options->port);
  return written > 0 && written < (int) BENCH_ENDPOINT_BYTES ? RLC_OK : RLC_ERR;
}

static void cleanup_ipc(const char *endpoint) {
  if (endpoint != NULL &&
      strncmp(endpoint, "ipc://", sizeof("ipc://") - 1) == 0)
    unlink(endpoint + sizeof("ipc://") - 1);
}

static int find_idle_worker(const gateway_worker_t *workers, unsigned count) {
  unsigned i;
  for (i = 0; i < count; i++) {
    if (workers[i].registered && !workers[i].busy) return (int) i;
  }
  return -1;
}

static unsigned busy_workers(const gateway_worker_t *workers, unsigned count) {
  unsigned i;
  unsigned busy = 0;
  for (i = 0; i < count; i++) busy += workers[i].busy ? 1u : 0u;
  return busy;
}

static int queue_pending_frame(gateway_route_t *route, uint8_t *payload,
                               size_t payload_length) {
  gateway_frame_t *frame;
  if (route == NULL || payload == NULL || payload_length == 0)
    return RLC_ERR;
  frame = calloc(1, sizeof(*frame));
  if (frame == NULL) return RLC_ERR;
  frame->data = payload;
  frame->length = payload_length;
  if (route->pending_tail == NULL) {
    route->pending_head = frame;
  } else {
    route->pending_tail->next = frame;
  }
  route->pending_tail = frame;
  route->pending_count++;
  return RLC_OK;
}

static void free_pending_frames(gateway_route_t *route) {
  gateway_frame_t *frame;
  if (route == NULL) return;
  frame = route->pending_head;
  while (frame != NULL) {
    gateway_frame_t *next = frame->next;
    free(frame->data);
    free(frame);
    frame = next;
  }
  route->pending_head = NULL;
  route->pending_tail = NULL;
  route->pending_count = 0;
}

static int assign_route(void *backend, const gateway_options_t *options,
                        gateway_route_t *routes, gateway_worker_t *workers,
                        unsigned route_index, unsigned worker_index,
                        gateway_metrics_t *metrics) {
  gateway_route_t *route = &routes[route_index];
  gateway_worker_t *worker = &workers[worker_index];
  gateway_frame_t *frame;
  uint8_t assignment[ASSIGNMENT_BYTES] = {0};
  long long waited = 0;
  if (route->pending_head == NULL) return RLC_ERR;
  bench_write_header_sid(assignment, BENCH_MSG_GATEWAY_ASSIGN, options->count,
                         route->pair_id, 0, route->execution_id,
                         route->pending_head->data + 32);
  write_u32_be(assignment + BENCH_HEADER_SIZE, (uint32_t) options->mode);
  write_u32_be(assignment + BENCH_HEADER_SIZE + 4,
               options->context_participants);
  write_u64_be(assignment + BENCH_HEADER_SIZE + 8, options->context_epoch);
  write_u64_be(assignment + BENCH_HEADER_SIZE + 16, options->context_expiry);
  write_u64_be(assignment + BENCH_HEADER_SIZE + 24,
               route->context_arc_index);
  memcpy(assignment + BENCH_HEADER_SIZE + 32, route->context_seed,
         BENCH_CONTEXT_SEED_BYTES);
  if (send_routed(backend, worker->identity, worker->identity_length,
                  assignment, sizeof(assignment)) != RLC_OK) return RLC_ERR;
  frame = route->pending_head;
  while (frame != NULL) {
    if (send_routed(backend, worker->identity, worker->identity_length,
                    frame->data, frame->length) != RLC_OK) return RLC_ERR;
    metrics->backend_sent++;
    frame = frame->next;
  }
  if (route->queued_at_ns != 0) {
    waited = bench_monotonic_ns() - route->queued_at_ns;
    metrics->total_queue_wait_ns += waited;
    if (waited > metrics->max_queue_wait_ns) metrics->max_queue_wait_ns = waited;
  }
  worker->busy = 1;
  worker->route_index = route->pair_id;
  route->worker_index = worker_index;
  route->assigned = 1;
  route->queued = 0;
  free_pending_frames(route);
  metrics->assignments++;
  metrics->internal_control_frames++;
  {
    unsigned busy = busy_workers(workers, options->worker_count);
    if (busy > metrics->peak_busy_workers) metrics->peak_busy_workers = busy;
  }
  return RLC_OK;
}

static int send_overload_abort(void *frontend, const gateway_route_t *route,
                               const bench_header_t *header,
                               gateway_metrics_t *metrics) {
  uint8_t abort_frame[BENCH_HEADER_SIZE];
  bench_write_header_sid(abort_frame, BENCH_MSG_ABORT, header->count,
                         header->pair_id, 0, header->execution_id, header->sid);
  if (send_routed(frontend, route->client_id, route->client_id_length,
                  abort_frame, sizeof(abort_frame)) != RLC_OK) return RLC_ERR;
  metrics->frontend_sent++;
  metrics->bytes_to_clients += sizeof(abort_frame);
  metrics->rejected_sessions++;
  return RLC_OK;
}

static int replay_completion(
    void *frontend, const gateway_options_t *options, gateway_route_t *route,
    const uint8_t *identity, size_t identity_length,
    const bench_header_t *query_header, const uint8_t *query,
    size_t query_length, gateway_metrics_t *metrics) {
  uint8_t done[BENCH_COMPLETION_FRAME_BYTES];
  bench_header_t stored_header;
  if (query_header->type != BENCH_MSG_COMPLETION_QUERY ||
      query_header->count != options->count ||
      query_header->first_ordinal != 0 ||
      query_length != BENCH_COMPLETION_FRAME_BYTES ||
      query_header->pair_id != route->pair_id ||
      query_header->execution_id != route->execution_id ||
      (route->client_seen &&
       !identity_equal(route->client_id, route->client_id_length,
                       identity, identity_length))) return RLC_ERR;
  metrics->completion_replay_requests++;
  if (bench_completion_journal_load(
          options->completion_dir, query_header->pair_id,
          query_header->execution_id, query_header->sid,
          query + BENCH_HEADER_SIZE, done) != RLC_OK) return RLC_ERR;
  if (bench_read_header(done, sizeof(done), &stored_header) != RLC_OK ||
      stored_header.count != query_header->count) return RLC_ERR;
  /* A prior failed directory sync may have left a readable record. */
  if (bench_completion_journal_store(options->completion_dir, done,
                                     sizeof(done)) != RLC_OK) return RLC_ERR;
  if (!route->client_seen) {
    memcpy(route->client_id, identity, identity_length);
    route->client_id_length = identity_length;
    route->client_seen = 1;
  }
  if (send_routed(frontend, identity, identity_length, done, sizeof(done)) !=
      RLC_OK) return RLC_ERR;
  metrics->frontend_sent++;
  metrics->bytes_to_clients += sizeof(done);
  metrics->completion_replays++;
  return RLC_OK;
}

static int acknowledge_persisted_completion(
    void *backend, const gateway_worker_t *worker,
    const bench_header_t *done_header, const uint8_t *done,
    size_t done_length, gateway_metrics_t *metrics) {
  uint8_t acknowledgement[BENCH_COMPLETION_FRAME_BYTES];
  if (worker == NULL || done_header == NULL || done == NULL ||
      done_length != BENCH_COMPLETION_FRAME_BYTES) return RLC_ERR;
  bench_write_header_sid(
      acknowledgement, BENCH_MSG_GATEWAY_COMPLETION_ACK,
      done_header->count, done_header->pair_id, 0,
      done_header->execution_id, done_header->sid);
  memcpy(acknowledgement + BENCH_HEADER_SIZE,
         done + BENCH_HEADER_SIZE, BENCH_DIGEST_BYTES);
  if (send_routed(backend, worker->identity, worker->identity_length,
                  acknowledgement, sizeof(acknowledgement)) != RLC_OK) {
    return RLC_ERR;
  }
  metrics->internal_control_frames++;
  return RLC_OK;
}

int main(int argc, char **argv) {
  gateway_options_t options;
  gateway_route_t *routes = NULL;
  gateway_worker_t *workers = NULL;
  unsigned *queue = NULL;
  unsigned queue_head = 0, queue_tail = 0, queue_depth = 0;
  gateway_metrics_t metrics = {0};
  bench_zap_service_t zap;
  bench_resource_mark_t before, after, delta;
  void *context = NULL, *frontend = NULL, *backend = NULL;
  char frontend_endpoint[BENCH_ENDPOINT_BYTES] = {0};
  unsigned registered = 0, completed = 0;
  long long all_completed_at = 0;
  long long last_activity;
  int64_t maximum_message_size;
  int linger = 0, mandatory = 1, status = 1;
  mode_t previous_umask;
  unsigned i;

  memset(&zap, 0, sizeof(zap));
  if (bench_resource_mark(&before) != RLC_OK ||
      parse_options(argc, argv, &options) != RLC_OK ||
      make_frontend(frontend_endpoint, &options) != RLC_OK) {
    fprintf(stderr, "invalid gateway arguments\n");
    return 2;
  }
  routes = calloc(options.expected_sessions, sizeof(*routes));
  workers = calloc(options.worker_count, sizeof(*workers));
  queue = calloc(options.expected_sessions, sizeof(*queue));
  context = zmq_ctx_new();
  if (routes == NULL || workers == NULL || queue == NULL || context == NULL ||
      load_manifest(&options, routes) != RLC_OK ||
      bench_completion_journal_prepare(options.completion_dir) != RLC_OK ||
      bench_zap_start(&zap, context, &options.auth) != RLC_OK) goto cleanup;
  frontend = zmq_socket(context, ZMQ_ROUTER);
  backend = zmq_socket(context, ZMQ_ROUTER);
  maximum_message_size = maximum_client_frame_bytes(&options);
  if (frontend == NULL || backend == NULL ||
      zmq_setsockopt(frontend, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_setsockopt(backend, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_setsockopt(frontend, ZMQ_ROUTER_MANDATORY, &mandatory,
                     sizeof(mandatory)) != 0 ||
      zmq_setsockopt(backend, ZMQ_ROUTER_MANDATORY, &mandatory,
                     sizeof(mandatory)) != 0 ||
      zmq_setsockopt(frontend, ZMQ_MAXMSGSIZE, &maximum_message_size,
                     sizeof(maximum_message_size)) != 0 ||
      bench_curve_configure_server(frontend, &options.auth) != RLC_OK ||
      zmq_bind(frontend, frontend_endpoint) != 0) goto cleanup;
  cleanup_ipc(options.backend);
  previous_umask = umask(0077);
  if (zmq_bind(backend, options.backend) != 0) {
    umask(previous_umask);
    goto cleanup;
  }
  umask(previous_umask);
  last_activity = bench_monotonic_ns();

  while (1) {
    if (completed >= options.expected_sessions) {
      if (options.completion_grace_ms == 0) break;
      if (all_completed_at == 0) all_completed_at = bench_monotonic_ns();
      if ((bench_monotonic_ns() - all_completed_at) / 1000000LL >=
          (long long) options.completion_grace_ms) break;
    }
    zmq_pollitem_t items[2] = {
        {frontend, 0, registered == options.worker_count ? ZMQ_POLLIN : 0, 0},
        {backend, 0, ZMQ_POLLIN, 0},
    };
    int rc = zmq_poll(items, 2, 100);
    if (rc < 0) goto cleanup;
    if (rc == 0) {
      long long idle_ms = (bench_monotonic_ns() - last_activity) / 1000000LL;
      if (idle_ms > (long long) options.io_timeout_ms) {
        fprintf(stderr, "gateway inactivity timeout\n");
        goto cleanup;
      }
      continue;
    }
    if (items[1].revents & ZMQ_POLLIN) {
      uint8_t identity[MAX_ROUTING_ID_BYTES];
      size_t identity_length = 0, payload_length = 0;
      uint8_t *payload = NULL;
      bench_header_t header;
      if (recv_routed(backend, identity, &identity_length,
                      &payload, &payload_length) != RLC_OK ||
          bench_read_header(payload, payload_length, &header) != RLC_OK) {
        free(payload);
        goto cleanup;
      }
      if (header.type == BENCH_MSG_GATEWAY_REGISTER) {
        char expected[96];
        unsigned worker_index = header.pair_id;
        int written = snprintf(expected, sizeof(expected), "worker:%u",
                               worker_index);
        if (worker_index >= options.worker_count ||
            workers[worker_index].registered || written <= 0 ||
            (size_t) written != identity_length ||
            memcmp(identity, expected, identity_length) != 0) {
          free(payload);
          goto cleanup;
        }
        memcpy(workers[worker_index].identity, identity, identity_length);
        workers[worker_index].identity_length = identity_length;
        workers[worker_index].registered = 1;
        registered++;
        if (registered == options.worker_count) {
          printf("GATEWAY_READY\t%u\t%s\n", registered, frontend_endpoint);
          fflush(stdout);
        }
      } else {
        int worker_index = -1;
        gateway_worker_t *worker;
        gateway_route_t *route;
        for (i = 0; i < options.worker_count; i++) {
          if (workers[i].registered &&
              identity_equal(workers[i].identity,
                             workers[i].identity_length,
                             identity, identity_length)) {
            worker_index = (int) i;
            break;
          }
        }
        if (worker_index < 0 || !workers[worker_index].busy) {
          free(payload);
          goto cleanup;
        }
        worker = &workers[worker_index];
        route = &routes[worker->route_index];
        if (!route->assigned || route->terminal ||
            header.pair_id != route->pair_id ||
            header.execution_id != route->execution_id) {
          free(payload);
          goto cleanup;
        }
        metrics.backend_received++;
        if (header.type == BENCH_MSG_DONE) {
          if (bench_completion_journal_store(options.completion_dir, payload,
                                             payload_length) != RLC_OK) {
            free(payload);
            goto cleanup;
          }
          metrics.completion_records_written++;
          if (acknowledge_persisted_completion(
                  backend, worker, &header, payload, payload_length,
                  &metrics) != RLC_OK) {
            free(payload);
            goto cleanup;
          }
        }
        if (header.type == BENCH_MSG_DONE &&
            options.test_drop_first_done_after_persist &&
            metrics.test_dropped_done_frames == 0) {
          metrics.test_dropped_done_frames++;
        } else {
          if (send_routed(frontend, route->client_id, route->client_id_length,
                          payload, payload_length) != RLC_OK) {
            if (header.type != BENCH_MSG_DONE) {
              free(payload);
              goto cleanup;
            }
          } else {
            metrics.frontend_sent++;
            metrics.bytes_to_clients += payload_length;
          }
        }
        if (header.type == BENCH_MSG_DONE || header.type == BENCH_MSG_ABORT ||
            (header.type == BENCH_MSG_FINAL_STATUS &&
             status_is_terminal(payload, payload_length))) {
          route->terminal = 1;
          worker->busy = 0;
          completed++;
          if (queue_depth != 0) {
            unsigned queued_route = queue[queue_head++ % options.expected_sessions];
            queue_depth--;
            if (assign_route(backend, &options, routes, workers,
                             queued_route, (unsigned) worker_index,
                             &metrics) != RLC_OK) {
              free(payload);
              goto cleanup;
            }
          }
        }
      }
      free(payload);
      last_activity = bench_monotonic_ns();
    }
    if (items[0].revents & ZMQ_POLLIN) {
      uint8_t identity[MAX_ROUTING_ID_BYTES];
      size_t identity_length = 0, payload_length = 0;
      uint8_t *payload = NULL;
      bench_header_t header;
      gateway_route_t *route;
      if (recv_routed(frontend, identity, &identity_length,
                      &payload, &payload_length) != RLC_OK) {
        free(payload);
        continue;
      }
      if (bench_read_header(payload, payload_length, &header) != RLC_OK ||
          header.pair_id >= options.expected_sessions) {
        free(payload);
        continue;
      }
      route = &routes[header.pair_id];
      if (header.execution_id == route->execution_id &&
          header.type == BENCH_MSG_COMPLETION_QUERY) {
        metrics.frontend_received++;
        metrics.bytes_from_clients += payload_length;
        if (client_identity_available(routes, options.expected_sessions,
                                      header.pair_id, identity,
                                      identity_length) &&
            replay_completion(frontend, &options, route, identity,
                              identity_length, &header, payload,
                              payload_length, &metrics) == RLC_OK) {
          if (!route->terminal) {
            route->terminal = 1;
            completed++;
          }
          last_activity = bench_monotonic_ns();
        }
        free(payload);
        continue;
      }
      if (route->terminal || header.execution_id != route->execution_id ||
          (!route->client_seen && header.type != BENCH_MSG_BATCH_INIT) ||
          !client_identity_available(routes, options.expected_sessions,
                                     header.pair_id, identity,
                                     identity_length)) {
        free(payload);
        continue;
      }
      if (!route->client_seen) {
        int idle;
        const unsigned expected_init_count =
            options.mode == BENCH_MODE_ORIGINAL_ITEMWISE ? 1u : options.count;
        if (header.count != expected_init_count || header.first_ordinal != 0 ||
            payload_length != expected_init_frame_bytes(
                                  &options, expected_init_count, 0)) {
          fprintf(stderr,
                  "gateway rejected initial frame: pair=%u type=%u count=%u "
                  "first=%u bytes=%zu expected_count=%u expected_bytes=%zu\n",
                  header.pair_id, header.type, header.count,
                  header.first_ordinal, payload_length, expected_init_count,
                  expected_init_frame_bytes(&options, expected_init_count,
                                            0));
          free(payload);
          continue;
        }
        memcpy(route->client_id, identity, identity_length);
        route->client_id_length = identity_length;
        route->client_seen = 1;
        if (queue_pending_frame(route, payload, payload_length) != RLC_OK) {
          free(payload);
          goto cleanup;
        }
        payload = NULL;
        idle = find_idle_worker(workers, options.worker_count);
        if (idle >= 0) {
          if (assign_route(backend, &options, routes, workers,
                           route->pair_id, (unsigned) idle,
                           &metrics) != RLC_OK) goto cleanup;
        } else if (queue_depth < options.max_queue) {
          route->queued = 1;
          route->queued_at_ns = bench_monotonic_ns();
          queue[queue_tail++ % options.expected_sessions] = route->pair_id;
          queue_depth++;
          metrics.queued_sessions++;
          if (queue_depth > metrics.peak_queue_depth)
            metrics.peak_queue_depth = queue_depth;
        } else {
          if (send_overload_abort(frontend, route, &header, &metrics) != RLC_OK)
            goto cleanup;
          route->terminal = 1;
          completed++;
        }
      } else {
        if (!identity_equal(route->client_id, route->client_id_length,
                            identity, identity_length)) {
          free(payload);
          continue;
        }
        if (route->queued) {
          if (options.mode != BENCH_MODE_ORIGINAL_ITEMWISE ||
              header.type != BENCH_MSG_BATCH_INIT || header.count != 1 ||
              header.first_ordinal != route->pending_count ||
              route->pending_count >= options.count ||
              payload_length != expected_init_frame_bytes(
                                    &options, 1, header.first_ordinal)) {
            free(payload);
            continue;
          }
          if (queue_pending_frame(route, payload, payload_length) != RLC_OK) {
            free(payload);
            goto cleanup;
          }
          payload = NULL;
        } else {
          gateway_worker_t *worker;
          if (!route->assigned) {
            free(payload);
            goto cleanup;
          }
          worker = &workers[route->worker_index];
          if (!worker->busy || worker->route_index != route->pair_id ||
              send_routed(backend, worker->identity, worker->identity_length,
                          payload, payload_length) != RLC_OK) {
            free(payload);
            goto cleanup;
          }
          metrics.backend_sent++;
        }
      }
      metrics.frontend_received++;
      metrics.bytes_from_clients += payload_length;
      free(payload);
      last_activity = bench_monotonic_ns();
    }
  }

  for (i = 0; i < options.worker_count; i++) {
    uint8_t shutdown[BENCH_HEADER_SIZE];
    bench_write_header(shutdown, BENCH_MSG_GATEWAY_SHUTDOWN, 0, i, 0, 0);
    if (send_routed(backend, workers[i].identity, workers[i].identity_length,
                    shutdown, sizeof(shutdown)) != RLC_OK) goto cleanup;
    metrics.internal_control_frames++;
  }
  if (bench_resource_mark(&after) != RLC_OK) goto cleanup;
  bench_resource_delta(&before, &after, &delta);
  printf("GATEWAY_RESULT\t%u\t%u\t%u\t%u\t%u\t%u\t%zu\t%zu\t%lld\t%lld\t%ld\n",
         options.expected_sessions, completed, metrics.frontend_received,
         metrics.frontend_sent, metrics.backend_received, metrics.backend_sent,
         metrics.bytes_from_clients, metrics.bytes_to_clients,
         delta.user_cpu_ns, delta.system_cpu_ns, delta.max_rss_kb);
  printf("GATEWAY_POOL_RESULT\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%lld\t%lld\t%u\t%u\t%u\t%u\n",
         options.worker_count, options.max_queue, metrics.peak_busy_workers,
         metrics.peak_queue_depth, metrics.assignments,
         metrics.queued_sessions, metrics.rejected_sessions,
         metrics.internal_control_frames, metrics.total_queue_wait_ns,
         metrics.max_queue_wait_ns, metrics.completion_records_written,
         metrics.completion_replay_requests, metrics.completion_replays,
         metrics.test_dropped_done_frames);
  fflush(stdout);
  status = metrics.rejected_sessions == 0 ? 0 : 3;

cleanup:
  if (status == 1) {
    fprintf(stderr,
            "gateway failed: registered=%u/%u completed=%u/%u assignments=%u "
            "queued=%u rejected=%u\n",
            registered, options.worker_count, completed,
            options.expected_sessions, metrics.assignments,
            metrics.queued_sessions, metrics.rejected_sessions);
  } else if (status == 3) {
    fprintf(stderr, "gateway overload: rejected_sessions=%u\n",
            metrics.rejected_sessions);
  }
  if (frontend != NULL) zmq_close(frontend);
  if (backend != NULL) zmq_close(backend);
  if (zap.initialized) bench_zap_stop(&zap);
  if (context != NULL) zmq_ctx_destroy(context);
  cleanup_ipc(options.backend);
  if (routes != NULL) {
    for (i = 0; i < options.expected_sessions; i++)
      free_pending_frames(&routes[i]);
  }
  free(queue);
  free(workers);
  free(routes);
  return status;
}
