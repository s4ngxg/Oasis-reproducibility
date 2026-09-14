#include <stdio.h>
#include <stdint.h>
#include "host_schedule.h"
#define CHECK(condition) do { if (!(condition)) return 1; } while (0)
int main(void) {
  host_schedule schedule;
  uint64_t deadline=77;
  CHECK(host_schedule_init(&schedule,3,100,15,2));
  CHECK(schedule.preswap_window_ns==21 && schedule.refund_ns==166);
  CHECK(host_relock_deadline(&schedule,1,&deadline) && deadline==136);
  CHECK(host_relock_deadline(&schedule,2,&deadline) && deadline==151);
  CHECK(!host_relock_deadline(&schedule,3,&deadline) && deadline==151);
  CHECK(!host_preswap_live(&schedule,99));
  CHECK(host_preswap_live(&schedule,100) && host_preswap_live(&schedule,120));
  CHECK(!host_preswap_live(&schedule,121));
  CHECK(!host_relock_ready(&schedule,1,135));
  CHECK(host_relock_ready(&schedule,1,136));
  CHECK(host_relock_ready(&schedule,1,137));
  CHECK(!host_relock_ready(&schedule,2,150));
  CHECK(host_relock_ready(&schedule,2,151));
  CHECK(!host_relock_ready(&schedule,0,UINT64_MAX));
  CHECK(!host_relock_ready(&schedule,3,UINT64_MAX));
  CHECK(!host_relock_ready(NULL,1,UINT64_MAX));
  CHECK(!host_refund_ready(&schedule,165));
  CHECK(host_refund_ready(&schedule,166));
  CHECK(host_refund_ready(&schedule,167));
  CHECK(!host_refund_ready(NULL,UINT64_MAX));
  CHECK(!host_schedule_init(&schedule,3,UINT64_MAX,15,2) && schedule.refund_ns==166);
  CHECK(!host_schedule_init(&schedule,3,0,1,UINT64_MAX));
  CHECK(!host_schedule_init(&schedule,128,0,UINT64_MAX/128,1));
  CHECK(!host_schedule_init(&schedule,2,0,15,2));
  CHECK(!host_schedule_init(&schedule,3,0,0,2));
  CHECK(host_schedule_init(&schedule,128,0,1,1) && schedule.refund_ns==132);
  puts("host schedule: boundaries, ordering and overflow rejection PASS");
  return 0;
}
