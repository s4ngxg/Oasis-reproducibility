#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include "zmq.h"
#include "util.h"
#include "host_handoff.h"
#include "host_witness.h"
#include "transport_auth.h"

/* Loopback authentication gate; all credentials and witnesses stay in memory.
 * This fixture does not implement distributed Preparation or a wallet. */
static int sealed_input(int fd,size_t size) {
  struct stat st;
  int seals=fcntl(fd,F_GET_SEALS),required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  return seals>=0 && (seals&required)==required && !fstat(fd,&st) && st.st_size==(off_t)size;
}

int main(int argc,char **argv) {
  unsigned char preparation[12+128*64]={0},
      handoff[HOST_HEADER_BYTES+255*HOST_RECORD_BYTES]={0};
  int output_fd=-1;
  unsigned receiver_index=0,n=3;
  if (argc!=1 && argc!=5) return 2;
  if (argc==5) {
    unsigned long v[4];
    for (unsigned i=0;i<4;i++) {
      char *end; errno=0; v[i]=strtoul(argv[i+1],&end,10);
      if (errno || end==argv[i+1] || *end || v[i]>1048575 || (i<3 && v[i]<3)) return 2;
    }
    struct stat st;
    /* Seal before the first header read: the decoded count must describe the
     * same immutable object that is consumed below. */
    if (fstat((int)v[0],&st) || st.st_size<12 || st.st_size>(off_t)sizeof(preparation) ||
        !sealed_input((int)v[0],(size_t)st.st_size) ||
        pread((int)v[0],preparation,12,0)!=12 || memcmp(preparation,"OASISYF1",8)) return 2;
    n=((unsigned)preparation[8]<<24)|((unsigned)preparation[9]<<16)|
        ((unsigned)preparation[10]<<8)|preparation[11];
    if (n<3 || n>128 || v[3]>=n) return 2;
  size_t preparation_size=12+64*n,
      handoff_size=HOST_HEADER_BYTES+HOST_RECORD_BYTES*(2*n-1);
    unsigned char output_magic[8];
    if (!sealed_input((int)v[0],preparation_size) ||
        !sealed_input((int)v[1],handoff_size) || fcntl((int)v[2],F_GET_SEALS)<0 ||
        fstat((int)v[2],&st) || st.st_size!=(off_t)(8+32*(2*n-1)) ||
        pread((int)v[0],preparation,preparation_size,0)!=(ssize_t)preparation_size ||
        pread((int)v[1],handoff,handoff_size,0)!=(ssize_t)handoff_size ||
        memcmp(handoff,HOST_HANDOFF_MAGIC,8) ||
        pread((int)v[2],output_magic,8,0)!=8 || memcmp(output_magic,"OASISW01",8) ||
        (fcntl((int)v[2],F_GET_SEALS)&F_SEAL_WRITE)) return 2;
    output_fd=(int)v[2]; receiver_index=(unsigned)v[3];
  }
  char server_public[41],server_secret[41],public_keys[129][41],secret_keys[129][41];
  const char *allowed[128];
  void *context=NULL,*receiver=NULL,*sender[129]={NULL};
  bench_zap_service_t zap={0};
  host_witness_state *state=NULL;
  ec_t points[128],statement; bn_t witnesses[128],result,identifier,order;
  ec_public_key_t joint;
  schnorr_signature_t signature;
  unsigned initialized=0;
  unsigned char host_context[32]={7},frame[HOST_WITNESS_FRAME_BYTES];
  char endpoint[128]; size_t endpoint_length=sizeof(endpoint);
  const char *domain="OASIS-HOST-WITNESS-v1";
  int status=1,enabled=1,timeout=1000,linger=0,unknown_send_blocked=0;
  const char *volatile stage="setup";
  struct rlimit core_limit={0,0};
  if (setrlimit(RLIMIT_CORE,&core_limit)!=0 || init()!=RLC_OK) return 1;
  bn_null(result);
  bn_null(identifier); bn_null(order); ec_null(statement);
  ec_public_key_null(joint); schnorr_signature_null(signature);
  RLC_TRY {
    bn_new(result);
    bn_new(identifier); bn_new(order); ec_new(statement); ec_curve_get_ord(order);
    ec_public_key_new(joint); schnorr_signature_new(signature);
    if (output_fd>=0) memcpy(host_context,handoff+8,32);
    stage="curve-key";
    if (zmq_curve_keypair(server_public,server_secret)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<n+1;i++)
      if (zmq_curve_keypair(public_keys[i],secret_keys[i])) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<n;i++) {
      stage="scalar";
      allowed[i]=public_keys[i];
      ec_null(points[i]); bn_null(witnesses[i]); initialized++;
      ec_new(points[i]); bn_new(witnesses[i]); bn_set_dig(witnesses[i],i+1);
      if (output_fd>=0) {
        bn_read_bin(witnesses[i],preparation+12+64*i,32);
        if (bn_is_zero(witnesses[i]) || bn_cmp(witnesses[i],order)!=RLC_LT) RLC_THROW(ERR_NO_VALID);
      }
      ec_mul_gen(points[i],witnesses[i]);
    }
    stage="zap";
    context=zmq_ctx_new();
    if (!context || host_zap_start(&zap,context,domain,allowed,n)!=RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    stage="bind";
    state=host_witness_create(n,(const ec_t *)points,host_context);
    receiver=zmq_socket(context,ZMQ_PULL);
    if (!state || !receiver ||
        zmq_setsockopt(receiver,ZMQ_LINGER,&linger,sizeof(linger)) ||
        zmq_setsockopt(receiver,ZMQ_RCVTIMEO,&timeout,sizeof(timeout)) ||
        zmq_setsockopt(receiver,ZMQ_CURVE_SERVER,&enabled,sizeof(enabled)) ||
        zmq_setsockopt(receiver,ZMQ_CURVE_SECRETKEY,server_secret,40) ||
        zmq_setsockopt(receiver,ZMQ_ZAP_DOMAIN,domain,strlen(domain)) ||
        zmq_bind(receiver,"tcp://127.0.0.1:*") ||
        zmq_getsockopt(receiver,ZMQ_LAST_ENDPOINT,endpoint,&endpoint_length)) RLC_THROW(ERR_NO_VALID);
    stage="connect";
    for (unsigned i=0;i<n+1;i++) {
      sender[i]=zmq_socket(context,ZMQ_PUSH);
      if (!sender[i] || zmq_setsockopt(sender[i],ZMQ_LINGER,&linger,sizeof(linger)) ||
          zmq_setsockopt(sender[i],ZMQ_SNDTIMEO,&timeout,sizeof(timeout)) ||
          zmq_setsockopt(sender[i],ZMQ_CURVE_PUBLICKEY,public_keys[i],40) ||
          zmq_setsockopt(sender[i],ZMQ_CURVE_SECRETKEY,secret_keys[i],40) ||
          zmq_setsockopt(sender[i],ZMQ_CURVE_SERVERKEY,server_public,40) ||
          zmq_connect(sender[i],endpoint)) RLC_THROW(ERR_NO_VALID);
    }
    stage="send";
    for (unsigned i=0;i<n;i++) {
      unsigned participant=(i+n-1)%n;
      if (!host_witness_encode(frame,sizeof(frame),participant,host_context,witnesses[participant]) ||
          zmq_send(sender[participant],frame,sizeof(frame),0)!=(int)sizeof(frame))
        RLC_THROW(ERR_NO_VALID);
    }
    stage="receive";
    for (unsigned i=0;i<n;i++) {
      zmq_msg_t message;
      if (zmq_msg_init(&message)) RLC_THROW(ERR_NO_VALID);
      int received=zmq_msg_recv(&message,receiver,0);
      const char *identity=received>=0 ? zmq_msg_gets(&message,"User-Id") : NULL;
      int accepted=host_witness_receive_authenticated(state,identity,
          zmq_msg_data(&message),zmq_msg_size(&message));
      zmq_msg_close(&message);
      if (!accepted || (i<n-1 && host_witness_global(state,result))) RLC_THROW(ERR_NO_VALID);
    }
    /* An authorized sender cannot impersonate another participant in payload. */
    stage="impersonation";
    if (!host_witness_encode(frame,sizeof(frame),1,host_context,witnesses[1]) ||
        zmq_send(sender[0],frame,sizeof(frame),0)!=(int)sizeof(frame)) RLC_THROW(ERR_NO_VALID);
    zmq_msg_t message;
    if (zmq_msg_init(&message)) RLC_THROW(ERR_NO_VALID);
    int received=zmq_msg_recv(&message,receiver,0);
    const char *identity=received>=0 ? zmq_msg_gets(&message,"User-Id") : NULL;
    int rejected=identity && !strcmp(identity,"participant:0") &&
        !host_witness_receive_authenticated(state,identity,zmq_msg_data(&message),zmq_msg_size(&message));
    zmq_msg_close(&message);
    if (!rejected) RLC_THROW(ERR_NO_VALID);
    /* Unknown CURVE key must not deliver even an otherwise valid witness. */
    stage="unknown-key";
    /* Authentication may reject the peer before PUSH obtains a writable pipe.
     * Both send backpressure and a queued-but-undelivered frame are valid
     * rejection outcomes; in either case the receiver must get no message. */
    int unknown_sent=zmq_send(sender[n],frame,sizeof(frame),0);
    unknown_send_blocked=unknown_sent<0 && zmq_errno()==EAGAIN;
    if (unknown_sent!=(int)sizeof(frame) && !unknown_send_blocked) RLC_THROW(ERR_NO_VALID);
    if (zmq_recv(receiver,frame,sizeof(frame),0)>=0 || zmq_errno()!=EAGAIN)
      RLC_THROW(ERR_NO_VALID);
    if (!host_witness_global(state,result) || (output_fd<0 && bn_cmp_dig(result,6)!=RLC_EQ))
      RLC_THROW(ERR_NO_VALID);
    if (output_fd>=0) {
      stage="compose";
      bn_read_bin(identifier,preparation+12+64*receiver_index+32,32);
      ec_read_bin(statement,handoff+HOST_HEADER_BYTES+HOST_STATEMENT_OFFSET,33);
      if (!host_witness_withdraw(state,(const bn_t *)&identifier,1,statement,result)) RLC_THROW(ERR_NO_VALID);
      ec_read_bin(joint->pk,handoff+HOST_HEADER_BYTES+HOST_JOINT_KEY_OFFSET,33);
      bn_read_bin(signature->e,handoff+HOST_HEADER_BYTES+HOST_CHALLENGE_OFFSET,32);
      bn_read_bin(signature->s,handoff+HOST_HEADER_BYTES+HOST_SCALAR_OFFSET,32);
      if (bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT ||
          adaptor_schnorr_preverify(signature,
              handoff+HOST_HEADER_BYTES+HOST_TX_DIGEST_OFFSET,32,
              statement,joint)!=1) RLC_THROW(ERR_NO_VALID);
      bn_add(signature->s,signature->s,result); bn_mod(signature->s,signature->s,order);
      ec_set_infty(statement);
      if (adaptor_schnorr_preverify(signature,
              handoff+HOST_HEADER_BYTES+HOST_TX_DIGEST_OFFSET,32,
              statement,joint)!=1) RLC_THROW(ERR_NO_VALID);
      unsigned char scalar[32]; bn_write_bin(scalar,32,result);
      ssize_t written=pwrite(output_fd,scalar,32,8); memzero(scalar,sizeof(scalar));
      if (written!=32) RLC_THROW(ERR_NO_VALID);
    }
    printf("{\"curve_witness_delivery\":true,\"distinct_peer_identity\":true,"
         "\"payload_impersonation_rejected\":true,\"unknown_key_rejected\":true,"
         "\"send_all_before_receive\":true,\"live_withdrawal_witness\":%s,"
         "\"unknown_key_send_blocked\":%s}\n",
         output_fd>=0 ? "true" : "false",unknown_send_blocked ? "true" : "false");
    status=0;
  } RLC_CATCH_ANY { fprintf(stderr,"WITNESS_GATE_STAGE=%s\n",stage); status=1; }
  RLC_FINALLY {
    for (unsigned i=0;i<n+1;i++) if (sender[i]) zmq_close(sender[i]);
    if (receiver) zmq_close(receiver);
    bench_zap_stop(&zap); if (context) zmq_ctx_term(context);
    host_witness_destroy(state);
    for (unsigned i=0;i<initialized;i++) {
      bn_zero(witnesses[i]); bn_free(witnesses[i]); ec_free(points[i]);
    }
    if (result!=NULL) bn_zero(result);
    bn_free(result); memzero(frame,sizeof(frame));
    if (identifier!=NULL) bn_zero(identifier);
    bn_free(identifier); bn_free(order); ec_free(statement);
    if (joint!=NULL) ec_public_key_free(joint);
    if (signature!=NULL) schnorr_signature_free(signature);
    memzero(preparation,sizeof(preparation));
    memzero(secret_keys,sizeof(secret_keys)); memzero(server_secret,sizeof(server_secret));
  }
  clean(); return status;
}
