#include <stddef.h>
#include "host_schedule.h"

int host_schedule_init(host_schedule *output,unsigned participants,
    uint64_t origin_ns,uint64_t delta_ns,uint64_t epsilon_ns) {
  host_schedule candidate;
  if (!output || participants<3 || participants>128 || !delta_ns || !epsilon_ns ||
      epsilon_ns>UINT64_MAX/3) return 0;
  uint64_t overhead=3*epsilon_ns;
  if (delta_ns>UINT64_MAX-overhead) return 0;
  uint64_t t=delta_ns+overhead;
  if (delta_ns>(UINT64_MAX-t)/participants) return 0;
  uint64_t duration=participants*delta_ns+t;
  if (origin_ns>UINT64_MAX-duration) return 0;
  candidate.participants=participants; candidate.origin_ns=origin_ns;
  candidate.delta_ns=delta_ns; candidate.preswap_window_ns=t;
  candidate.refund_ns=origin_ns+duration;
  *output=candidate; return 1;
}

int host_relock_deadline(const host_schedule *schedule,unsigned level,uint64_t *deadline_ns) {
  if (!schedule || !deadline_ns || level<1 || level>=schedule->participants) return 0;
  /* schedule must come from successful host_schedule_init and remain immutable. */
  *deadline_ns=schedule->origin_ns+schedule->preswap_window_ns+level*schedule->delta_ns;
  return 1;
}

int host_preswap_live(const host_schedule *schedule,uint64_t now_ns) {
  return schedule && now_ns>=schedule->origin_ns &&
         now_ns-schedule->origin_ns<schedule->preswap_window_ns;
}

int host_relock_ready(const host_schedule *schedule,unsigned level,uint64_t now_ns) {
  uint64_t deadline;
  return host_relock_deadline(schedule,level,&deadline) && now_ns>=deadline;
}

int host_refund_ready(const host_schedule *schedule,uint64_t now_ns) {
  return schedule && now_ns>=schedule->refund_ns;
}
