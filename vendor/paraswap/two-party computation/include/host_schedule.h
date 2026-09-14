#ifndef OASIS_HOST_SCHEDULE_H
#define OASIS_HOST_SCHEDULE_H
#include <stdint.h>

typedef struct {
  unsigned participants;
  uint64_t origin_ns, delta_ns, preswap_window_ns, refund_ns;
} host_schedule;
/* Figure 4/5: t=Delta+3*epsilon; T=n*Delta+t. origin_ns is a local
 * monotonic protocol origin supplied by the host, not a synchronized clock.
 * Start VTD solving at Pre-swap entry; these are action/admission cutoffs,
 * not instructions to postpone starting the sequential solver.
 * Values are host-validated policy, never peer-selected relative timeouts.
 * This schedule cannot guarantee timed privacy or a blockchain upper bound. */
int host_schedule_init(host_schedule *output,unsigned participants,
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns);
int host_relock_deadline(const host_schedule *schedule,unsigned level,
                         uint64_t *deadline_ns);
int host_preswap_live(const host_schedule *schedule,uint64_t now_ns);
/* Local host action eligibility, not ledger consensus or proof that a VTD
 * completed. The caller must also validate the recovered witness/signature.
 * level names the destination address (1..n-1), not the item ordinal. */
int host_relock_ready(const host_schedule *schedule,unsigned level,uint64_t now_ns);
int host_refund_ready(const host_schedule *schedule,uint64_t now_ns);
#endif
