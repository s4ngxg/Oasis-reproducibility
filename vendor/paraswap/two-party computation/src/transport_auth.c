#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "zmq.h"
#include "transport_auth.h"
#ifdef BENCH_ALLOCATION_PROFILE
#include "allocation_counter.h"
#endif

static int read_curve_key(const char *path, int secret,
                          char out[BENCH_CURVE_KEY_CHARS + 1]) {
  FILE *file;
  char buffer[BENCH_CURVE_KEY_CHARS + 4];
  size_t length;
  uint8_t decoded[32];
  struct stat metadata;

  if (path == NULL || path[0] == '\0') return RLC_ERR;
  if (stat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
    fprintf(stderr, "cannot stat CURVE key: %s\n", path);
    return RLC_ERR;
  }
  if (secret && (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    fprintf(stderr, "CURVE secret key must have mode 0600: %s\n", path);
    return RLC_ERR;
  }
  file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "cannot open CURVE key: %s\n", path);
    return RLC_ERR;
  }
  if (fgets(buffer, sizeof(buffer), file) == NULL || ferror(file)) {
    fclose(file);
    return RLC_ERR;
  }
  if (fgetc(file) != EOF) {
    fclose(file);
    fprintf(stderr, "CURVE key file has trailing data: %s\n", path);
    return RLC_ERR;
  }
  fclose(file);
  length = strcspn(buffer, "\r\n");
  if (length != BENCH_CURVE_KEY_CHARS ||
      (buffer[length] != '\0' &&
       !(buffer[length] == '\n' && buffer[length + 1] == '\0') &&
       !(buffer[length] == '\r' && buffer[length + 1] == '\n' &&
         buffer[length + 2] == '\0'))) {
    fprintf(stderr, "invalid CURVE key encoding: %s\n", path);
    return RLC_ERR;
  }
  buffer[length] = '\0';
  if (zmq_z85_decode(decoded, buffer) == NULL) {
    fprintf(stderr, "invalid CURVE Z85 key: %s\n", path);
    return RLC_ERR;
  }
  memcpy(out, buffer, BENCH_CURVE_KEY_CHARS + 1);
  return RLC_OK;
}

int bench_curve_configure_client(void *socket,
                                 const bench_options_t *options) {
  char public_key[BENCH_CURVE_KEY_CHARS + 1];
  char secret_key[BENCH_CURVE_KEY_CHARS + 1];
  char server_key[BENCH_CURVE_KEY_CHARS + 1];
  if (socket == NULL || options == NULL ||
      read_curve_key(options->curve_public_key_file, 0, public_key) != RLC_OK ||
      read_curve_key(options->curve_secret_key_file, 1, secret_key) != RLC_OK ||
      read_curve_key(options->curve_server_key_file, 0, server_key) != RLC_OK) {
    return RLC_ERR;
  }
  if (zmq_setsockopt(socket, ZMQ_CURVE_PUBLICKEY, public_key,
                     BENCH_CURVE_KEY_CHARS) != 0 ||
      zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY, secret_key,
                     BENCH_CURVE_KEY_CHARS) != 0 ||
      zmq_setsockopt(socket, ZMQ_CURVE_SERVERKEY, server_key,
                     BENCH_CURVE_KEY_CHARS) != 0) {
    perror("configure client CURVE");
    return RLC_ERR;
  }
  return RLC_OK;
}

int bench_curve_configure_server(void *socket,
                                 const bench_options_t *options) {
  char secret_key[BENCH_CURVE_KEY_CHARS + 1];
  int enabled = 1;
  size_t domain_length;
  if (socket == NULL || options == NULL || options->zap_domain[0] == '\0' ||
      read_curve_key(options->curve_secret_key_file, 1, secret_key) != RLC_OK) {
    return RLC_ERR;
  }
  domain_length = strlen(options->zap_domain);
  if (zmq_setsockopt(socket, ZMQ_CURVE_SERVER, &enabled, sizeof(enabled)) != 0 ||
      zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY, secret_key,
                     BENCH_CURVE_KEY_CHARS) != 0 ||
      zmq_setsockopt(socket, ZMQ_ZAP_DOMAIN, options->zap_domain,
                     domain_length) != 0) {
    perror("configure server CURVE/ZAP");
    return RLC_ERR;
  }
  return RLC_OK;
}

static int recv_part(void *socket, zmq_msg_t *message, int expect_more) {
  int more = 0;
  size_t more_size = sizeof(more);
  if (zmq_msg_init(message) != 0) return RLC_ERR;
  if (zmq_msg_recv(message, socket, 0) < 0 ||
      zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_size) != 0 ||
      (!!more) != (!!expect_more)) {
    zmq_msg_close(message);
    return RLC_ERR;
  }
  return RLC_OK;
}

static int part_equal(const zmq_msg_t *message, const void *data,
                      size_t length) {
  return zmq_msg_size(message) == length &&
         memcmp(zmq_msg_data((zmq_msg_t *) message), data, length) == 0;
}

static int send_part(void *socket, const void *data, size_t length, int more) {
  return zmq_send(socket, data, length, more ? ZMQ_SNDMORE : 0) >= 0
             ? RLC_OK : RLC_ERR;
}

static void signal_ready(bench_zap_service_t *service, int status) {
  pthread_mutex_lock(&service->mutex);
  service->status = status;
  service->ready = 1;
  pthread_cond_signal(&service->condition);
  pthread_mutex_unlock(&service->mutex);
}

static void *zap_worker(void *argument) {
  bench_zap_service_t *service = argument;
  void *socket = zmq_socket(service->context, ZMQ_REP);
  zmq_msg_t request[7];
  uint8_t allowed_binary[32];
  unsigned received;
  int authorized;
  int linger = 0;
  unsigned i;
  char user_id[32];

  if (socket == NULL ||
      zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger)) != 0 ||
      zmq_bind(socket, "inproc://zeromq.zap.01") != 0 ||
      (!service->participant_count &&
       zmq_z85_decode(allowed_binary, service->allowed_client_key) == NULL)) {
    if (socket != NULL) zmq_close(socket);
    signal_ready(service, RLC_ERR);
    return NULL;
  }
  signal_ready(service, RLC_OK);

  for (;;) {
    received = 0;
    authorized = 0;
    for (i = 0; i < 7; i++) {
      if (recv_part(socket, &request[i], i < 6) != RLC_OK) goto cleanup;
      received++;
    }
    int envelope_valid = part_equal(&request[0], "1.0", 3) &&
                 part_equal(&request[2], service->domain,
                            strlen(service->domain)) &&
                 part_equal(&request[5], "CURVE", 5);
    user_id[0]='\0';
    if (envelope_valid && service->participant_count) {
      for (unsigned participant=0;participant<service->participant_count;participant++) {
        if (part_equal(&request[6],service->participant_keys[participant],32)) {
          authorized=1;
          snprintf(user_id,sizeof(user_id),"participant:%u",participant);
          break;
        }
      }
    } else if (envelope_valid && part_equal(&request[6],allowed_binary,32)) {
      authorized=1; memcpy(user_id,"initiator",10);
    }

    if (send_part(socket, zmq_msg_data(&request[0]),
                  zmq_msg_size(&request[0]), 1) != RLC_OK ||
        send_part(socket, zmq_msg_data(&request[1]),
                  zmq_msg_size(&request[1]), 1) != RLC_OK ||
        send_part(socket, authorized ? "200" : "400", 3, 1) != RLC_OK ||
        send_part(socket, authorized ? "OK" : "DENIED",
                  authorized ? 2 : 6, 1) != RLC_OK ||
        send_part(socket, user_id, strlen(user_id),
                  1) != RLC_OK ||
        send_part(socket, "", 0, 0) != RLC_OK) {
      goto cleanup;
    }
    for (i = 0; i < received; i++) zmq_msg_close(&request[i]);
  }

cleanup:
  for (i = 0; i < received; i++) zmq_msg_close(&request[i]);
  zmq_close(socket);
  return NULL;
}

static int start_service(bench_zap_service_t *service) {
  if (pthread_mutex_init(&service->mutex, NULL) != 0) return RLC_ERR;
  if (pthread_cond_init(&service->condition, NULL) != 0) {
    pthread_mutex_destroy(&service->mutex); return RLC_ERR;
  }
  service->initialized = 1;
  if (pthread_create(&service->thread, NULL, zap_worker, service) != 0) {
    bench_zap_stop(service); return RLC_ERR;
  }
  service->thread_started = 1;
  pthread_mutex_lock(&service->mutex);
  while (!service->ready) pthread_cond_wait(&service->condition, &service->mutex);
  pthread_mutex_unlock(&service->mutex);
  return service->status;
}

int host_zap_start(bench_zap_service_t *service, void *context,
    const char *domain, const char *const *public_keys, unsigned participants) {
  if (!service || !context || !domain || !domain[0] ||
      strlen(domain)>=sizeof(service->domain) || !public_keys ||
      participants<3 || participants>128) return RLC_ERR;
  memset(service,0,sizeof(*service));
  for (unsigned i=0;i<participants;i++) {
    if (!public_keys[i] || strlen(public_keys[i])!=BENCH_CURVE_KEY_CHARS ||
        !zmq_z85_decode(service->participant_keys[i],public_keys[i])) return RLC_ERR;
    for (unsigned j=0;j<i;j++)
      if (!memcmp(service->participant_keys[i],service->participant_keys[j],32)) return RLC_ERR;
  }
  service->participant_count=participants;
  memcpy(service->domain,domain,strlen(domain)+1); service->context=context;
  return start_service(service);
}

int bench_zap_start(bench_zap_service_t *service, void *context,
                    const bench_options_t *options) {
  if (service == NULL || context == NULL || options == NULL ||
      options->zap_domain[0] == '\0') {
    return RLC_ERR;
  }
  memset(service, 0, sizeof(*service));
  if (read_curve_key(options->curve_allowed_client_key_file, 0,
                     service->allowed_client_key) != RLC_OK ||
      strlen(options->zap_domain) >= sizeof(service->domain)) {
    return RLC_ERR;
  }
  memcpy(service->domain, options->zap_domain,
         strlen(options->zap_domain) + 1);
  service->context = context;
  return start_service(service);
}

void bench_zap_stop(bench_zap_service_t *service) {
  if (service == NULL) return;
  if (service->thread_started) {
    zmq_ctx_shutdown(service->context);
    pthread_join(service->thread, NULL);
  }
  if (service->initialized) {
    pthread_cond_destroy(&service->condition);
    pthread_mutex_destroy(&service->mutex);
  }
  memset(service, 0, sizeof(*service));
}
