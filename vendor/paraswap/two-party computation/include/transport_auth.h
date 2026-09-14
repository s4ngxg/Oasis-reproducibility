#ifndef OASIS_TRANSPORT_AUTH_H
#define OASIS_TRANSPORT_AUTH_H

#include <pthread.h>

#include "preswap_protocol.h"

#define BENCH_CURVE_KEY_CHARS 40u

typedef struct {
  void *context;
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  int initialized;
  int thread_started;
  int ready;
  int status;
  char allowed_client_key[BENCH_CURVE_KEY_CHARS + 1];
  char domain[BENCH_ZAP_DOMAIN_BYTES];
  unsigned participant_count;
  uint8_t participant_keys[128][32];
} bench_zap_service_t;

int bench_curve_configure_client(void *socket,
                                 const bench_options_t *options);
int bench_curve_configure_server(void *socket,
                                 const bench_options_t *options);
int bench_zap_start(bench_zap_service_t *service, void *context,
                    const bench_options_t *options);
/* Distinct, prepared CURVE public keys. ZAP User-Id is participant:<index>.
 * Keys are public; the owning participant retains the corresponding secret.
 * Do not run alongside another ZAP service in the same ZeroMQ context. */
int host_zap_start(bench_zap_service_t *service, void *context,
    const char *domain, const char *const *public_keys, unsigned participants);
void bench_zap_stop(bench_zap_service_t *service);

#endif
