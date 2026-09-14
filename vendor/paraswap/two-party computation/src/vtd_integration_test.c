#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include "util.h"
#include "vtd_commit.h"
#include "vtd_setup.h"
#include "vtd_wire.h"
#include "host_refund.h"
#include "host_handoff.h"

#define SHARES 256u
#define ROWS 128u

static int live_key_matches(int fd,unsigned count,const ec_t joint,uint8_t *context,
                            uint8_t *refund_digest) {
  uint8_t header[HOST_HEADER_BYTES],record[HOST_RECORD_BYTES],encoded[33];
  struct stat metadata;
  if (!host_memory_fd(fd) || fstat(fd,&metadata) ||
      metadata.st_size!=(off_t)(HOST_HEADER_BYTES+(2*count-1)*HOST_RECORD_BYTES) ||
      pread(fd,header,sizeof(header),0)!=(ssize_t)sizeof(header) ||
      memcmp(header,HOST_HANDOFF_MAGIC,8) ||
      pread(fd,record,sizeof(record),HOST_HEADER_BYTES+(count-1)*HOST_RECORD_BYTES)
        !=(ssize_t)sizeof(record) || ec_is_infty(joint)) return 0;
  ec_write_bin(encoded,33,joint,1);
  if (memcmp(encoded,record+HOST_JOINT_KEY_OFFSET,33)) return 0;
  if (context) md_map_sh256(context,header,sizeof(header));
  if (refund_digest && host_fixture_refund_digest(refund_digest,header)!=RLC_OK) return 0;
  return 1;
}

static int live_relock_matches(int fd,unsigned count,unsigned level,const ec_t statement) {
  uint8_t header[HOST_HEADER_BYTES],record[HOST_RECORD_BYTES],encoded[33];
  struct stat info;
  if (level>=count-1 || !host_memory_fd(fd) || fstat(fd,&info) ||
      info.st_size!=(off_t)(HOST_HEADER_BYTES+(2*count-1)*HOST_RECORD_BYTES) ||
      pread(fd,header,sizeof(header),0)!=(ssize_t)sizeof(header) ||
      memcmp(header,HOST_HANDOFF_MAGIC,8) ||
      pread(fd,record,sizeof(record),HOST_HEADER_BYTES+(count+level)*HOST_RECORD_BYTES)
        !=(ssize_t)sizeof(record)) return 0;
  ec_write_bin(encoded,33,statement,1);
  return !memcmp(encoded,record+HOST_STATEMENT_OFFSET,33);
}

int main(int argc,char **argv) {
  unsigned long input[4]={0};
  int refund_fd=-1;
  int external[4]={-1,-1,-1,-1};
  int relock_level=-1;
  if (argc!=1 && argc!=5 && argc!=6 && argc!=7 && argc!=11 && argc!=12) return 2;
  if (argc==12) {
    char *end; errno=0; unsigned long level=strtoul(argv[11],&end,10);
    if (errno || end==argv[11] || *end || level>126) return 2;
    relock_level=(int)level;
  }
  if (argc>=7) {
    char *end; struct stat info;
    errno=0; unsigned long fd=strtoul(argv[6],&end,10);
    if (errno || end==argv[6] || *end || fd<3 || fd>1048575 ||
        !host_memory_fd((int)fd) || fstat((int)fd,&info) || info.st_size) return 2;
    refund_fd=(int)fd;
  }
  if (argc>=11) for (unsigned i=0;i<4;i++) {
    char *end; struct stat info;
    errno=0; unsigned long fd=strtoul(argv[7+i],&end,10);
    if (errno || end==argv[7+i] || *end || fd<3 || fd>1048575 ||
        !host_memory_fd((int)fd) || fstat((int)fd,&info) || info.st_size ||
        (int)fd==refund_fd) return 2;
    external[i]=(int)fd;
    for (unsigned j=0;j<i;j++) if (external[i]==external[j]) return 2;
  }
  for (unsigned i=0;i<4 && argc>=5;i++) {
    char *end;
    errno=0; input[i]=strtoul(argv[i+1],&end,10);
    if (errno || *end || end==argv[i+1] || input[i]>1048575) return 2;
  }
  if (argc>=5 && (input[0]<3 || input[0]>128 || input[1]<3 || input[2]<3 || input[3]<3))
    return 2;
  if (relock_level>=0 && (unsigned)relock_level>=input[0]-1) return 2;
  bn_t secret,order,recovered;
  bn_t sender;
  ec_t joint,sender_point;
  schnorr_signature_t refund_signature;
  ec_t key,points[SHARES];
  ec_t received_points[SHARES];
  mpz_t ru[SHARES],rv[SHARES],rdu[ROWS],rdv[ROWS],rz[ROWS],rr[ROWS];
  mpz_t ropened[SHARES/2],rcoins[SHARES/2];
  unsigned char *wire=NULL;
  size_t wire_bytes=0;
  mpz_t n,g,h,limit,u[SHARES],v[SHARES],du[ROWS],dv[ROWS];
  mpz_t response[ROWS],random_response[ROWS],opened[SHARES/2],coins[SHARES/2];
  unsigned char bytes[32],context[32]={0},refund_digest[32]={0};
  if (argc>=6) {
    if (strlen(argv[5])!=64) return 2;
    for (unsigned i=0;i<64;i++) {
      char c=argv[5][i];
      unsigned digit=c>='0' && c<='9' ? (unsigned)(c-'0') :
                     c>='a' && c<='f' ? (unsigned)(c-'a'+10) : 16;
      if (digit>15) return 2;
      context[i/2]=(uint8_t)(16*context[i/2]+digit);
    }
  }
  unsigned initialized=0;
  uint64_t work=0;
  int status=1;
  struct rlimit no_core={0,0};
  if (setrlimit(RLIMIT_CORE,&no_core) || init()!=RLC_OK) return 1;
  bn_null(secret); bn_null(order); bn_null(recovered); ec_null(key);
  bn_null(sender); ec_null(joint); ec_null(sender_point); schnorr_signature_null(refund_signature);
  mpz_inits(n,g,h,limit,NULL);
  for (unsigned i=0;i<SHARES;i++) mpz_inits(u[i],v[i],NULL);
  for (unsigned i=0;i<ROWS;i++) mpz_inits(du[i],dv[i],response[i],random_response[i],NULL);
  for (unsigned i=0;i<SHARES/2;i++) mpz_inits(opened[i],coins[i],NULL);
  for (unsigned i=0;i<SHARES;i++) mpz_inits(ru[i],rv[i],NULL);
  for (unsigned i=0;i<ROWS;i++) mpz_inits(rdu[i],rdv[i],rz[i],rr[i],NULL);
  for (unsigned i=0;i<SHARES/2;i++) mpz_inits(ropened[i],rcoins[i],NULL);
  fputs("vtd integration: generating fresh 2048-bit setup\n",stderr);
  if (!vtd_setup_generate(n,g,h,2048,32,4000000)) {
    fputs("vtd integration: setup generation failed (candidate budget or randomness)\n",stderr);
    goto cleanup;
  }
  fputs("vtd integration: setup generated\n",stderr);
  RLC_TRY {
    bn_new(secret); bn_new(order); bn_new(recovered); ec_new(key);
    bn_new(sender); ec_new(joint); ec_new(sender_point); schnorr_signature_new(refund_signature);
    ec_curve_get_ord(order);
    do { bn_rand_mod(secret,order); } while (bn_is_zero(secret));
    ec_mul_gen(key,secret);
    do {
      bn_rand_mod(sender,order); ec_mul_gen(sender_point,sender); ec_add(joint,key,sender_point);
    } while (bn_is_zero(sender) || ec_is_infty(joint));
    if (argc>=5) {
      unsigned count=(unsigned)input[0];
      if (relock_level>=0) {
        if (host_read_key((int)input[2],secret,key)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
      } else {
      if (host_read_address_key((int)input[1],count,count-1,sender,sender_point)!=RLC_OK ||
          host_read_address_key((int)input[2],count,count-1,secret,key)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      ec_add(joint,key,sender_point); ec_norm(joint,joint);
      if (ec_is_infty(joint)) RLC_THROW(ERR_NO_VALID);
      if (argc==5 && !live_key_matches((int)input[3],count,joint,context,refund_digest)) RLC_THROW(ERR_NO_VALID);
      }
    }
    bn_write_bin(bytes,32,order); mpz_import(limit,32,1,1,0,0,bytes);
    mpz_mul_2exp(limit,limit,153);
    for (unsigned i=0;i<SHARES;i++) {
      ec_null(points[i]); ec_null(received_points[i]); initialized++;
      ec_new(points[i]); ec_new(received_points[i]);
    }
    vtd_proof_output output={SHARES,ROWS,points,u,v,du,dv,response,random_response,opened,coins};
    fputs("vtd integration: committing 256 shares and 128 proof rows\n",stderr);
    if (!vtd_commit(&output,secret,key,context,32,n,g,h,limit)) {
      fputs("vtd integration: prover/self-verification failed\n",stderr);
      RLC_THROW(ERR_NO_VALID);
    }
    vtd_proof_view produced=vtd_commit_view(&output);
    vtd_proof_output received={SHARES,ROWS,received_points,ru,rv,rdu,rdv,rz,rr,ropened,rcoins};
    wire=malloc(VTD_WIRE_MAX_BYTES);
    if (!wire || !vtd_proof_encode(wire,VTD_WIRE_MAX_BYTES,&wire_bytes,&produced) ||
        !vtd_proof_decode(&received,wire,wire_bytes)) RLC_THROW(ERR_NO_VALID);
    /* The verifier/solver use only the decoded public proof, not prover arrays. */
    vtd_proof_view proof=vtd_commit_view(&received);
    fputs("vtd integration: independent verification\n",stderr);
    if (!vtd_verify_relations(&proof,SHARES,key,context,32,n,g,h,limit)) {
      fputs("vtd integration: decoded proof verification failed\n",stderr);
      RLC_THROW(ERR_NO_VALID);
    }
    if (argc>=11) {
      unsigned char metadata[81]={0},parameters[20000];
      size_t parameters_length=0;
      memcpy(metadata,"OASISVS1",8); memcpy(metadata+8,context,32);
      ec_write_bin(metadata+40,33,key,1); metadata[80]=32;
      if (!vtd_setup_encode(parameters,sizeof(parameters),&parameters_length,n,g,h,limit) ||
          pwrite(external[0],metadata,sizeof(metadata),0)!=(ssize_t)sizeof(metadata) ||
          pwrite(external[1],parameters,parameters_length,0)!=(ssize_t)parameters_length ||
          pwrite(external[2],wire,wire_bytes,0)!=(ssize_t)wire_bytes) RLC_THROW(ERR_NO_VALID);
    }
    if (argc>=6) {
      puts("VTD_PREPARED"); fflush(stdout);
      if (getchar()!='S') RLC_THROW(ERR_NO_VALID);
      puts("VTD_SOLVER_STARTING"); fflush(stdout);
    }
    fputs("vtd integration: sequential recovery\n",stderr);
    if (argc<11 && (!vtd_force_open(recovered,&work,32*(SHARES/2),&proof,SHARES,key,context,32,n,g,h,limit) ||
        bn_cmp(secret,recovered)!=RLC_EQ || work!=32)) RLC_THROW(ERR_NO_VALID);
    if (argc>=6 && getchar()!='D') RLC_THROW(ERR_NO_VALID);
    if (argc>=6 && !(relock_level>=0 ?
        live_relock_matches((int)input[3],(unsigned)input[0],(unsigned)relock_level,key) :
        live_key_matches((int)input[3],(unsigned)input[0],joint,NULL,refund_digest))) RLC_THROW(ERR_NO_VALID);
    if (argc>=11) {
      ec_t recovered_point; ec_null(recovered_point);
      int matches=0;
      RLC_TRY {
        ec_new(recovered_point);
        matches=host_read_key(external[3],recovered,recovered_point)==RLC_OK &&
                ec_cmp(recovered_point,key)==RLC_EQ && bn_cmp(recovered,secret)==RLC_EQ;
      } RLC_CATCH_ANY { matches=0; }
      RLC_FINALLY { ec_free(recovered_point); }
      if (!matches) RLC_THROW(ERR_NO_VALID);
    }
    /* Consume ForceOp output, not the prover's retained fixture secret. */
    if (argc==1) memcpy(refund_digest,context,32);
    if (relock_level<0 && !host_refund_sign(refund_signature,refund_digest,sender,recovered,key,joint))
      RLC_THROW(ERR_NO_VALID);
    context[0]^=1;
    if (vtd_verify_relations(&proof,SHARES,key,context,32,n,g,h,limit)) RLC_THROW(ERR_NO_VALID);
    if (refund_fd>=0) {
      uint8_t receipt[104];
      size_t receipt_length=sizeof(receipt);
      if (relock_level>=0) {
        memcpy(receipt,"OASISK01",8); bn_write_bin(receipt+8,32,recovered); receipt_length=40;
      } else {
      memcpy(receipt,"OASISR01",8); memcpy(receipt+8,refund_digest,32);
      bn_write_bin(receipt+40,32,refund_signature->e);
      bn_write_bin(receipt+72,32,refund_signature->s);
      }
      ssize_t written=pwrite(refund_fd,receipt,receipt_length,0);
      memzero(receipt,sizeof(receipt));
      if (written!=(ssize_t)receipt_length)
        RLC_THROW(ERR_NO_VALID);
    }
    printf("{\"modulus_bits\":2048,\"shares\":256,\"range_rows\":128,"
           "\"commit_verify_recover\":true,\"recovered_share_refund_signature\":%s,"
           "\"live_relock_statement_binding\":%s,"
           "\"decoded_public_proof_used\":true,"
           "\"wrong_context_rejected\":true,\"live_final_key_binding\":%s,"
           "\"prepared_before_preswap\":%s,"
           "\"external_solver_used\":%s,"
           "\"squarings\":%llu,\"timed_privacy_benchmarked\":false}\n",
           relock_level<0 ? "true" : "false",relock_level>=0 ? "true" : "false",
           argc>=5 && relock_level<0 ? "true" : "false",argc>=6 ? "true" : "false",
           argc>=11 ? "true" : "false",(unsigned long long)work);
    status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    for (unsigned i=0;i<initialized;i++) { ec_free(points[i]); ec_free(received_points[i]); }
    if (secret!=NULL) bn_zero(secret);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(secret); bn_free(order); bn_free(recovered); ec_free(key);
    if (sender!=NULL) bn_zero(sender);
    bn_free(sender); ec_free(joint); ec_free(sender_point);
    if (refund_signature!=NULL) schnorr_signature_free(refund_signature);
  }
cleanup:
  free(wire);
  if (status && refund_fd>=0 && ftruncate(refund_fd,0)) status=1;
  for (unsigned i=0;i<SHARES;i++) mpz_clears(u[i],v[i],NULL);
  for (unsigned i=0;i<ROWS;i++) mpz_clears(du[i],dv[i],response[i],random_response[i],NULL);
  for (unsigned i=0;i<SHARES/2;i++) mpz_clears(opened[i],coins[i],NULL);
  for (unsigned i=0;i<SHARES;i++) mpz_clears(ru[i],rv[i],NULL);
  for (unsigned i=0;i<ROWS;i++) mpz_clears(rdu[i],rdv[i],rz[i],rr[i],NULL);
  for (unsigned i=0;i<SHARES/2;i++) mpz_clears(ropened[i],rcoins[i],NULL);
  mpz_clears(n,g,h,limit,NULL); memzero(bytes,sizeof(bytes)); clean();
  return status;
}
