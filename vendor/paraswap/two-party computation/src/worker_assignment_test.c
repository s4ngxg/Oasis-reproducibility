/* Exercise the worker's actual decoder through native ZeroMQ frames. */
#define main worker_program_main
#include "preswap_server_v4.c"
#undef main

int main(void) {
  void *context=zmq_ctx_new(),*send=NULL,*receive=NULL;
  int status=1,timeout=1000;
  if (!context) return 1;
  send=zmq_socket(context,ZMQ_PAIR); receive=zmq_socket(context,ZMQ_PAIR);
  if (!send || !receive || zmq_setsockopt(receive,ZMQ_RCVTIMEO,&timeout,sizeof(timeout)) ||
      zmq_bind(send,"inproc://assignment-test") ||
      zmq_connect(receive,"inproc://assignment-test")) goto cleanup;
  const uint32_t participants[]={0,1,129,2147483651u,UINT32_MAX,3};
  for (unsigned i=0;i<sizeof(participants)/sizeof(participants[0]);i++) {
    uint8_t frame[ASSIGNMENT_BYTES]={0};
    bench_options_t options,before;
    memset(&options,0,sizeof(options)); options.execution_id=77;
    memcpy(&before,&options,sizeof(options));
    bench_write_header(frame,BENCH_MSG_GATEWAY_ASSIGN,5,0,0,1);
    write_u32(frame+BENCH_HEADER_SIZE,BENCH_MODE_BJP_MSM);
    write_u32(frame+BENCH_HEADER_SIZE+4,participants[i]);
    frame[BENCH_HEADER_SIZE+15]=1;
    frame[BENCH_HEADER_SIZE+23]=1;
    frame[BENCH_HEADER_SIZE+31]=1;
    int shutdown=0;
    if (zmq_send(send,frame,sizeof(frame),0)!=(int)sizeof(frame)) goto cleanup;
    int result=receive_assignment(receive,&options,&shutdown);
    if (participants[i]==3) {
      if (result!=RLC_OK || options.context_participants!=3 || options.count!=5 ||
          options.execution_id!=1 || shutdown) goto cleanup;
    } else if (result!=RLC_ERR || memcmp(&before,&options,sizeof(options)) || shutdown)
      goto cleanup;
  }
  puts("worker assignment: malformed counts, overflow and unchanged context PASS");
  status=0;
cleanup:
  if (send) zmq_close(send);
  if (receive) zmq_close(receive);
  zmq_ctx_term(context);
  return status;
}
