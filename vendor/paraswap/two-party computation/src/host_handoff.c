#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "host_handoff.h"

int host_fixture_refund_digest(uint8_t output[32],const uint8_t header[HOST_HEADER_BYTES]) {
  static const uint8_t domain[]="OASIS-FIXTURE-REFUND-v1";
  uint8_t input[sizeof(domain)-1+HOST_HEADER_BYTES];
  if (!output || !header || memcmp(header,HOST_HANDOFF_MAGIC,8)) return RLC_ERR;
  memcpy(input,domain,sizeof(domain)-1);
  memcpy(input+sizeof(domain)-1,header,HOST_HEADER_BYTES);
  md_map_sh256(output,input,sizeof(input));
  return RLC_OK;
}

/* Only Linux anonymous memory files are accepted. Never fall back to disk. */
int host_memory_fd(int fd) {
  char path[64], target[256];
  ssize_t length;
  if (fd < 3 || fcntl(fd, F_GET_SEALS) < 0) return 0;
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  length = readlink(path, target, sizeof(target) - 1);
  if (length < 0) return 0;
  target[length] = 0;
  return strncmp(target, "/memfd:oasis-", 13) == 0;
}

int host_read_key(int fd, bn_t secret, ec_t public_key) {
  struct stat info;
  uint8_t encoded[40]={0};
  bn_t value,order;
  ec_t point;
  int status=RLC_ERR;
  const int required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  if (!host_memory_fd(fd) || (fcntl(fd,F_GET_SEALS)&required)!=required ||
      fstat(fd,&info) || info.st_size!=sizeof(encoded)) return RLC_ERR;
  bn_null(value); bn_null(order); ec_null(point);
  RLC_TRY {
    size_t offset=0;
    while (offset<sizeof(encoded)) {
      ssize_t amount=pread(fd,encoded+offset,sizeof(encoded)-offset,(off_t)offset);
      if (amount<0 && errno==EINTR) continue;
      if (amount<=0) RLC_THROW(ERR_NO_VALID);
      offset+=(size_t)amount;
    }
    if (memcmp(encoded,"OASISK01",8)) RLC_THROW(ERR_NO_VALID);
    bn_new(value); bn_new(order); ec_new(point); ec_curve_get_ord(order);
    bn_read_bin(value,encoded+8,32);
    if (bn_is_zero(value) || bn_cmp(value,order)!=RLC_LT) RLC_THROW(ERR_NO_VALID);
    ec_mul_gen(point,value);
    bn_copy(secret,value); ec_copy(public_key,point); status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (value!=NULL) bn_zero(value);
    bn_free(value); bn_free(order); ec_free(point); memzero(encoded,sizeof(encoded));
  }
  return status;
}

static int read_address_vector(int fd, unsigned count, unsigned ordinal,
                          bn_t secret, ec_t public_key,bn_t *staging) {
  uint8_t encoded[12+128*32]={0};
  struct stat info;
  bn_t order,value,selected;
  ec_t point;
  int status=RLC_ERR;
  const int required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  if (count<3 || count>128 || ordinal>=count || !host_memory_fd(fd) ||
      (fcntl(fd,F_GET_SEALS)&required)!=required || fstat(fd,&info) ||
      info.st_size!=(off_t)(12+count*32)) return RLC_ERR;
  bn_null(order); bn_null(value); bn_null(selected); ec_null(point);
  RLC_TRY {
    size_t offset=0,length=12+count*32;
    while (offset<length) {
      ssize_t amount=pread(fd,encoded+offset,length-offset,(off_t)offset);
      if (amount<0 && errno==EINTR) continue;
      if (amount<=0) RLC_THROW(ERR_NO_VALID);
      offset+=(size_t)amount;
    }
    if (memcmp(encoded,"OASISA01",8) || encoded[8] || encoded[9] ||
        encoded[10] || encoded[11]!=count) RLC_THROW(ERR_NO_VALID);
    bn_new(order); bn_new(value); bn_new(selected); ec_new(point);
    ec_curve_get_ord(order);
    for (unsigned i=0;i<count;i++) {
      bn_read_bin(value,encoded+12+32*i,32);
      if (bn_is_zero(value) || bn_cmp(value,order)!=RLC_LT) RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<i;j++)
        if (!memcmp(encoded+12+32*i,encoded+12+32*j,32)) RLC_THROW(ERR_NO_VALID);
      if (i==ordinal) bn_copy(selected,value);
    }
    /* Admission owns staging and discards it on failure. Do not expose partial
     * vector imports through the single-key public API. */
    if (staging) for (unsigned i=0;i<count;i++)
      bn_read_bin(staging[i],encoded+12+32*i,32);
    ec_mul_gen(point,selected);
    bn_copy(secret,selected); ec_copy(public_key,point); status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (value!=NULL) bn_zero(value);
    if (selected!=NULL) bn_zero(selected);
    bn_free(order); bn_free(value); bn_free(selected); ec_free(point);
    memzero(encoded,sizeof(encoded));
  }
  return status;
}

int host_read_address_key(int fd,unsigned count,unsigned ordinal,
                          bn_t secret,ec_t public_key) {
  return read_address_vector(fd,count,ordinal,secret,public_key,NULL);
}

static int address_proof_context(uint8_t digest[32],const uint8_t preparation[32],
                                  unsigned count,unsigned ordinal) {
  static const char domain[]="OASIS-ADDRESS-OWNERSHIP-v1";
  uint8_t input[sizeof(domain)-1+32+8];
  size_t offset=sizeof(domain)-1;
  if (!preparation || count<3 || count>128 || ordinal>=count) return RLC_ERR;
  memcpy(input,domain,offset); memcpy(input+offset,preparation,32); offset+=32;
  for (unsigned i=0;i<4;i++) {
    input[offset+i]=(uint8_t)(count>>(24-8*i));
    input[offset+4+i]=(uint8_t)(ordinal>>(24-8*i));
  }
  md_map_sh256(digest,input,sizeof(input)); return RLC_OK;
}

int host_address_key_prove(uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const bn_t secret,const ec_t public_key,const uint8_t preparation[32],
    unsigned count,unsigned ordinal,bench_key_role_t role,uint64_t pair_id,uint64_t epoch) {
  uint8_t context[32];
  if (!proof || address_proof_context(context,preparation,count,ordinal)!=RLC_OK) return RLC_ERR;
  return bench_key_ownership_prove(proof,secret,public_key,context,role,pair_id,epoch);
}

int host_address_key_verify(const uint8_t proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES],
    const ec_t public_key,const uint8_t preparation[32],unsigned count,unsigned ordinal,
    bench_key_role_t role,uint64_t pair_id,uint64_t epoch) {
  uint8_t context[32];
  if (!proof || address_proof_context(context,preparation,count,ordinal)!=RLC_OK) return RLC_ERR;
  return bench_key_ownership_verify(proof,public_key,context,role,pair_id,epoch);
}

static int write_all(int fd, const uint8_t *bytes, size_t length) {
  while (length) {
    ssize_t written = write(fd, bytes, length);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return RLC_ERR;
    bytes += written;
    length -= (size_t) written;
  }
  return RLC_OK;
}

int host_write_address_public(int output_fd,int secret_fd,unsigned count,
    const uint8_t preparation[32],bench_key_role_t role,uint64_t pair_id,uint64_t epoch) {
  uint8_t header[12]={0},record[33+BENCH_KEY_OWNERSHIP_PROOF_BYTES];
  bn_t secret; ec_t point;
  int status=RLC_ERR;
  if (!preparation || count<3 || count>128 || output_fd==secret_fd ||
      !host_memory_fd(output_fd) || lseek(output_fd,0,SEEK_END)!=0) return RLC_ERR;
  bn_null(secret); ec_null(point);
  RLC_TRY {
    bn_new(secret); ec_new(point);
    memcpy(header,"OASISAP1",8); header[11]=(uint8_t)count;
    if (write_all(output_fd,header,sizeof(header))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<count;i++) {
      if (host_read_address_key(secret_fd,count,i,secret,point)!=RLC_OK ||
          host_address_key_prove(record+33,secret,point,preparation,count,i,
                                 role,pair_id,epoch)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
      ec_write_bin(record,33,point,1);
      if (write_all(output_fd,record,sizeof(record))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    }
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (secret!=NULL) bn_zero(secret);
    bn_free(secret); ec_free(point);
  }
  if (status!=RLC_OK) (void)ftruncate(output_fd,0);
  return status;
}

/* all_points is private admission staging storage, discarded on any failure. */
static int read_public_bundle(int fd,unsigned count,unsigned ordinal,ec_t output,
    const uint8_t preparation[32],bench_key_role_t role,uint64_t pair_id,uint64_t epoch,
    ec_t *all_points) {
  enum { STRIDE=33+BENCH_KEY_OWNERSHIP_PROOF_BYTES };
  uint8_t bytes[12+128*STRIDE],canonical[33];
  ec_t point,selected;
  struct stat info;
  const int required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  int status=RLC_ERR;
  if (!preparation || count<3 || count>128 || ordinal>=count || !host_memory_fd(fd) ||
      (fcntl(fd,F_GET_SEALS)&required)!=required || fstat(fd,&info) ||
      info.st_size!=(off_t)(12+count*STRIDE)) return RLC_ERR;
  ec_null(point); ec_null(selected);
  RLC_TRY {
    size_t offset=0,length=12+count*STRIDE;
    while (offset<length) {
      ssize_t amount=pread(fd,bytes+offset,length-offset,(off_t)offset);
      if (amount<0 && errno==EINTR) continue;
      if (amount<=0) RLC_THROW(ERR_NO_VALID);
      offset+=(size_t)amount;
    }
    if (memcmp(bytes,"OASISAP1",8) || bytes[8] || bytes[9] || bytes[10] ||
        bytes[11]!=count) RLC_THROW(ERR_NO_VALID);
    ec_new(point); ec_new(selected);
    for (unsigned i=0;i<count;i++) {
      uint8_t *record=bytes+12+i*STRIDE;
      ec_read_bin(point,record,33);
      if (ec_is_infty(point) || !ec_on_curve(point)) RLC_THROW(ERR_NO_VALID);
      ec_write_bin(canonical,33,point,1);
      if (memcmp(canonical,record,33)) RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<i;j++)
        if (!memcmp(record,bytes+12+j*STRIDE,33)) RLC_THROW(ERR_NO_VALID);
      if (host_address_key_verify(record+33,point,preparation,count,i,role,pair_id,epoch)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      if (i==ordinal) ec_copy(selected,point);
      if (all_points) ec_copy(all_points[i],point);
    }
    ec_copy(output,selected); status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY { ec_free(point); ec_free(selected); }
  return status;
}

int host_read_address_public(int fd,unsigned count,unsigned ordinal,ec_t output,
    const uint8_t preparation[32],bench_key_role_t role,uint64_t pair_id,uint64_t epoch) {
  return read_public_bundle(fd,count,ordinal,output,preparation,role,pair_id,epoch,NULL);
}

static int address_mode(const bench_options_t *options) {
  int any=options->host_address_keys_fd>=0 || options->host_client_keys_fd>=0 ||
          options->host_server_keys_fd>=0;
  if (!any) return 0;
  return options->host_address_keys_fd>=0 && options->host_client_keys_fd>=0 &&
         options->host_server_keys_fd>=0 && options->host_statements[0] ? 1 : -1;
}

struct host_admitted_keys {
  unsigned count,initialized,pair_id;
  uint64_t epoch;
  uint8_t preparation[32];
  bench_key_role_t local_role;
  bn_t private[128];
  ec_t client[128],server[128];
};

void host_release_address_keys(bench_options_t *options) {
  struct host_admitted_keys *keys=options->host_admitted_keys;
  if (!keys) return;
  for (unsigned i=0;i<keys->initialized;i++) {
    if (keys->private[i]!=NULL) bn_zero(keys->private[i]);
    bn_free(keys->private[i]); ec_free(keys->client[i]); ec_free(keys->server[i]);
  }
  free(keys); options->host_admitted_keys=NULL;
}

int host_admit_address_keys(bench_options_t *options,bench_key_role_t local_role) {
  int mode=address_mode(options),status=RLC_ERR;
  ec_t actual;
  if (!mode) return RLC_OK;
  if (mode<0 || options->host_admitted_keys || options->pool_worker ||
      options->context_participants<3 || options->context_participants>128 ||
      (local_role!=BENCH_KEY_ROLE_INITIATOR && local_role!=BENCH_KEY_ROLE_RESPONDER)) return RLC_ERR;
  struct host_admitted_keys *keys=calloc(1,sizeof(*keys));
  if (!keys) return RLC_ERR;
  options->host_admitted_keys=keys;
  keys->count=options->context_participants; keys->pair_id=options->pair_id;
  keys->epoch=options->context_epoch; keys->local_role=local_role;
  memcpy(keys->preparation,options->context_seed,32);
  ec_null(actual);
  RLC_TRY {
    ec_new(actual);
    for (unsigned i=0;i<keys->count;i++) {
      bn_null(keys->private[i]); ec_null(keys->client[i]); ec_null(keys->server[i]);
      keys->initialized++;
      bn_new(keys->private[i]); ec_new(keys->client[i]); ec_new(keys->server[i]);
    }
    if (read_public_bundle(options->host_client_keys_fd,keys->count,0,actual,
          keys->preparation,BENCH_KEY_ROLE_INITIATOR,keys->pair_id,keys->epoch,keys->client)!=RLC_OK ||
        read_public_bundle(options->host_server_keys_fd,keys->count,0,actual,
          keys->preparation,BENCH_KEY_ROLE_RESPONDER,keys->pair_id,keys->epoch,keys->server)!=RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    if (read_address_vector(options->host_address_keys_fd,keys->count,0,
          keys->private[0],actual,keys->private)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<keys->count;i++) {
      ec_mul_gen(actual,keys->private[i]);
      if (ec_cmp(actual,local_role==BENCH_KEY_ROLE_INITIATOR ? keys->client[i] : keys->server[i])!=RLC_EQ)
        RLC_THROW(ERR_NO_VALID);
    }
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY { ec_free(actual); }
  if (status!=RLC_OK) host_release_address_keys(options);
  return status;
}

static int admitted_context_matches(const bench_options_t *options) {
  const struct host_admitted_keys *keys=options->host_admitted_keys;
  return keys && keys->count==options->context_participants && keys->pair_id==options->pair_id &&
         keys->epoch==options->context_epoch && !memcmp(keys->preparation,options->context_seed,32);
}

int host_item_public(ec_t output,const ec_t base,const bench_options_t *options,
                     unsigned ordinal,bench_key_role_t role) {
  int mode=address_mode(options);
  if (mode<0 || ordinal>=options->count) return RLC_ERR;
  if (mode && options->host_admitted_keys) {
    unsigned level=host_key_ordinal(options,ordinal);
    if (!admitted_context_matches(options) || level>=options->context_participants) return RLC_ERR;
    ec_copy(output,role==BENCH_KEY_ROLE_INITIATOR ? options->host_admitted_keys->client[level] :
            options->host_admitted_keys->server[level]);
    return RLC_OK;
  }
  if (mode) return host_read_address_public(
      role==BENCH_KEY_ROLE_INITIATOR ? options->host_client_keys_fd : options->host_server_keys_fd,
      options->context_participants,host_key_ordinal(options,ordinal),output,
      options->context_seed,role,options->pair_id,options->context_epoch);
  return bench_derive_item_public(output,base,
      role==BENCH_KEY_ROLE_INITIATOR ? "CLIENT-SIGNING-KEY-v1" : "SERVER-SIGNING-KEY-v1",
      options->pair_id,host_key_ordinal(options,ordinal),options->count);
}

int host_item_secret(bn_t output,const bn_t base,const bench_options_t *options,
                     unsigned ordinal,bench_key_role_t role) {
  int mode=address_mode(options),status=RLC_ERR;
  bn_t value; ec_t actual,expected;
  if (mode<0 || ordinal>=options->count) return RLC_ERR;
  if (mode && options->host_admitted_keys) {
    unsigned level=host_key_ordinal(options,ordinal);
    if (!admitted_context_matches(options) || level>=options->context_participants ||
        options->host_admitted_keys->local_role!=role) return RLC_ERR;
    bn_copy(output,options->host_admitted_keys->private[level]); return RLC_OK;
  }
  if (!mode) return bench_derive_item_secret(output,base,
      role==BENCH_KEY_ROLE_INITIATOR ? "CLIENT-SIGNING-KEY-v1" : "SERVER-SIGNING-KEY-v1",
      options->pair_id,host_key_ordinal(options,ordinal),options->count);
  bn_null(value); ec_null(actual); ec_null(expected);
  RLC_TRY {
    bn_new(value); ec_new(actual); ec_new(expected);
    if (host_read_address_key(options->host_address_keys_fd,options->context_participants,
          host_key_ordinal(options,ordinal),value,actual)!=RLC_OK ||
        host_item_public(expected,actual,options,ordinal,role)!=RLC_OK ||
        ec_cmp(actual,expected)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
    bn_copy(output,value); status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (value!=NULL) bn_zero(value);
    bn_free(value); ec_free(actual); ec_free(expected);
  }
  return status;
}

int host_write_handoff(int fd, const bench_transcript_t *transcript,
                       const bn_t *challenges, const bn_t *scalars) {
  uint8_t header[HOST_HEADER_BYTES], record[HOST_RECORD_BYTES];
  unsigned i;
  int status = RLC_ERR;
  if (!host_memory_fd(fd) || lseek(fd, 0, SEEK_END) != 0) return RLC_ERR;
  memcpy(header, HOST_HANDOFF_MAGIC, 8);
  memcpy(header + 8, transcript->context_digest, 32);
  memcpy(header + 40, transcript->parent_sid, 32);
  memcpy(header + 72, transcript->batch_digest, 32);
  RLC_TRY {
    if (write_all(fd, header, sizeof(header)) != RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (i = 0; i < transcript->count; i++) {
      memcpy(record + HOST_TX_DIGEST_OFFSET,
             transcript->message_digests + 32u * i, 32);
      memcpy(record + HOST_ITEM_DIGEST_OFFSET,
             transcript->item_digests + 32u * i, 32);
      ec_write_bin(record + HOST_STATEMENT_OFFSET, 33,
                   transcript->statements[i], 1);
      ec_write_bin(record + HOST_JOINT_KEY_OFFSET, 33,
                   transcript->joint_public_keys[i], 1);
      bn_write_bin(record + HOST_CHALLENGE_OFFSET, 32, challenges[i]);
      bn_write_bin(record + HOST_SCALAR_OFFSET, 32, scalars[i]);
      if (write_all(fd, record, sizeof(record)) != RLC_OK) RLC_THROW(ERR_NO_VALID);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  if (status != RLC_OK) (void) ftruncate(fd, 0);
  return status;
}

int host_write_handoff_until(int fd,const bench_transcript_t *transcript,
    const bn_t *challenges,const bn_t *scalars,uint64_t deadline_ns) {
  long long now=bench_monotonic_ns();
  if (!host_memory_fd(fd)) return RLC_ERR;
  if (now<=0 || (deadline_ns && (uint64_t)now>=deadline_ns)) {
    (void)ftruncate(fd,0); return RLC_ERR;
  }
  if (host_write_handoff(fd,transcript,challenges,scalars)!=RLC_OK) return RLC_ERR;
  now=bench_monotonic_ns();
  if (now<=0 || (deadline_ns && (uint64_t)now>=deadline_ns)) {
    (void)ftruncate(fd,0); return RLC_ERR;
  }
  return RLC_OK;
}

int host_read_statement(ec_t point, const char *path, unsigned count,
                        unsigned ordinal) {
  FILE *file = fopen(path, "rb");
  uint8_t magic[8], encoded[33], canonical[33];
  int status = RLC_ERR;
  if (file == NULL) return RLC_ERR;
  if (ordinal >= count || count > BENCH_MAX_ITEMS ||
      fread(magic, 1, 8, file) != 8 || memcmp(magic, HOST_PUBLIC_MAGIC, 8) ||
      fseek(file, 0, SEEK_END) || ftell(file) != (long)(8u + 33u * count) ||
      fseek(file, (long)(8u + 33u * ordinal), SEEK_SET) ||
      fread(encoded, 1, 33, file) != 33) goto done;
  RLC_TRY {
    ec_read_bin(point, encoded, 33);
    if (ec_is_infty(point) || !ec_on_curve(point)) RLC_THROW(ERR_NO_VALID);
    ec_write_bin(canonical, 33, point, 1);
    if (memcmp(encoded, canonical, 33)) RLC_THROW(ERR_NO_VALID);
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
done:
  fclose(file);
  return status;
}
