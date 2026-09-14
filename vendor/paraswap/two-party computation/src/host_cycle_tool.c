#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include "host_handoff.h"
#include "host_ledger.h"
#include "host_recovery.h"

static int exact_read(int fd, uint8_t *buffer, size_t length, off_t offset) {
  while (length) {
    ssize_t amount = pread(fd, buffer, length, offset);
    if (amount < 0 && errno == EINTR) continue;
    if (amount <= 0) return RLC_ERR;
    buffer += amount; offset += amount; length -= (size_t)amount;
  }
  return RLC_OK;
}

static int exact_write(int fd, const uint8_t *buffer, size_t length) {
  while (length) {
    ssize_t amount = write(fd, buffer, length);
    if (amount < 0 && errno == EINTR) continue;
    if (amount <= 0) return RLC_ERR;
    buffer += amount; length -= (size_t)amount;
  }
  return RLC_OK;
}

static int file_size(int fd, size_t expected) {
  struct stat info;
  return host_memory_fd(fd) && !fstat(fd, &info) &&
         info.st_size == (off_t)expected;
}

/* Figure 4, Eq. 10/11: global witness plus a cyclic identifier prefix.
 * Independent delayed witnesses follow the n withdrawal witnesses per arc.
 * The coordinator is a test harness, not a distributed wallet or VTD prover. */
static int prepare(unsigned n, int private_fd, int public_fd,int participant_fd) {
  bn_t order, global, value, identifier[128];
  ec_t point;
  uint8_t secret[32], encoded[33];
  unsigned i, j, initialized = 0;
  int status = RLC_ERR;
  if (!file_size(private_fd, 0) || !file_size(public_fd, 0) ||
      private_fd == public_fd) return RLC_ERR;
  if (participant_fd>=0 && (!file_size(participant_fd,0) ||
      participant_fd==private_fd || participant_fd==public_fd)) return RLC_ERR;
  bn_null(order); bn_null(global); bn_null(value); ec_null(point);
  RLC_TRY {
    bn_new(order); bn_new(global); bn_new(value); ec_new(point);
    ec_curve_get_ord(order); bn_zero(global);
    if (participant_fd>=0) {
      uint8_t header[12]={'O','A','S','I','S','Y','F','1',0,0,0,(uint8_t)n};
      if (exact_write(participant_fd,header,sizeof(header))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    }
    for (i = 0; i < n; i++) {
      bn_null(identifier[i]); bn_new(identifier[i]); initialized++;
      do { bn_rand_mod(identifier[i], order); } while (bn_is_zero(identifier[i]));
      do { bn_rand_mod(value, order); } while (bn_is_zero(value));
      /* Retained only in an anonymous fixture descriptor, never in results.
       * Each record is y_i then the participant's cyclic identifier. */
      if (participant_fd>=0) {
        bn_write_bin(secret,32,value);
        if (exact_write(participant_fd,secret,32)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
        bn_write_bin(secret,32,identifier[i]);
        if (exact_write(participant_fd,secret,32)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
      }
      bn_add(global, global, value); bn_mod(global, global, order);
    }
    if (exact_write(private_fd, (const uint8_t *)"OASISW01", 8) != RLC_OK ||
        exact_write(public_fd, (const uint8_t *)HOST_PUBLIC_MAGIC, 8) != RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    for (i = 0; i < n; i++) {
      bn_copy(value, global);
      for (j = 0; j < 2*n-1; j++) {
        if (j < n) {
          bn_add(value, value, identifier[(i+1+j)%n]);
          bn_mod(value, value, order);
        } else {
          do { bn_rand_mod(value, order); } while (bn_is_zero(value));
        }
        if (bn_is_zero(value)) RLC_THROW(ERR_NO_VALID);
        ec_mul_gen(point, value);
        bn_write_bin(secret, 32, value); ec_write_bin(encoded, 33, point, 1);
        if (exact_write(private_fd, secret, 32) != RLC_OK ||
            exact_write(public_fd, encoded, 33) != RLC_OK) RLC_THROW(ERR_NO_VALID);
      }
    }
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    for (i = 0; i < initialized; i++) { bn_zero(identifier[i]); bn_free(identifier[i]); }
    if (global != NULL) bn_zero(global);
    if (value != NULL) bn_zero(value);
    bn_free(order); bn_free(global); bn_free(value); ec_free(point);
    memzero(secret, sizeof(secret));
  }
  if (status != RLC_OK) { (void)ftruncate(private_fd, 0); (void)ftruncate(public_fd, 0); }
  if (status!=RLC_OK && participant_fd>=0 && ftruncate(participant_fd,0)) return RLC_ERR;
  return status;
}

static int check(unsigned count, int handoff_fd, int witness_fd,int refund_fd,
    host_ledger *funded_withdraw,host_ledger *funded_relock) {
  bn_t order, witness, extracted, saved;
  ec_t statement, computed, infinity;
  schnorr_signature_t signature;
  ec_public_key_t public_key;
  uint8_t header[HOST_HEADER_BYTES], secret[32], record[HOST_RECORD_BYTES];
  uint8_t canonical[33], magic[8];
  unsigned i;
  unsigned n = (count+1)/2, initialized_keys = 0;
  ec_t keys[255];
  uint8_t digests[255*32], refund_digest[32];
  host_ledger *withdraw_ledger = NULL, *relock_ledger = NULL;
  host_schedule schedule;
  int status = RLC_ERR;
  long long started = bench_monotonic_ns();
  if (count < 5 || count > 255 || !(count & 1) ||
      !file_size(handoff_fd, HOST_HEADER_BYTES + count*HOST_RECORD_BYTES) ||
      !file_size(witness_fd, 8u + count*32u) ||
      exact_read(handoff_fd, header, sizeof(header), 0) != RLC_OK ||
      memcmp(header, HOST_HANDOFF_MAGIC, 8) ||
      exact_read(witness_fd, magic, 8, 0) != RLC_OK || memcmp(magic, "OASISW01", 8))
    return RLC_ERR;
  bn_null(order); bn_null(witness); bn_null(extracted); bn_null(saved);
  ec_null(statement); ec_null(computed); ec_null(infinity);
  schnorr_signature_null(signature); ec_public_key_null(public_key);
  RLC_TRY {
    bn_new(order); bn_new(witness); bn_new(extracted); bn_new(saved);
    ec_new(statement); ec_new(computed); ec_new(infinity);
    schnorr_signature_new(signature); ec_public_key_new(public_key);
    ec_curve_get_ord(order); ec_set_infty(infinity);
    /* The trusted local producer supplies this registry. This checks signature
     * consumption, not independent validation of a distributed Preparation. */
    for (i = 0; i < count; i++) {
      if (exact_read(handoff_fd, record, sizeof(record),
                     HOST_HEADER_BYTES+i*HOST_RECORD_BYTES) != RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      ec_null(keys[i]); ec_new(keys[i]); initialized_keys++;
      ec_read_bin(keys[i], record+HOST_JOINT_KEY_OFFSET, 33);
      memcpy(digests+32*i, record+HOST_TX_DIGEST_OFFSET, 32);
    }
    /* Reserved fixture digest; no refund signature or recovery claim here. */
    if (host_fixture_refund_digest(refund_digest,header)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    /* Controlled clock for transition conformance, not calibrated VTD time. */
    if (!host_schedule_init(&schedule,n,100,15,2)) RLC_THROW(ERR_NO_VALID);
    withdraw_ledger = funded_withdraw ? funded_withdraw : host_ledger_create_timed(n, digests, keys, refund_digest,100,15,2);
    relock_ledger = funded_relock ? funded_relock : host_ledger_create_timed(n, digests, keys, refund_digest,100,15,2);
    if (!withdraw_ledger || !relock_ledger) RLC_THROW(ERR_NO_VALID);
    for (i = 0; i < count; i++) {
      if (exact_read(handoff_fd, record, sizeof(record),
                     HOST_HEADER_BYTES + i*HOST_RECORD_BYTES) != RLC_OK ||
          exact_read(witness_fd, secret, 32, 8u+i*32u) != RLC_OK)
        RLC_THROW(ERR_NO_VALID);
      bn_read_bin(witness, secret, 32);
      if (bn_is_zero(witness) || bn_cmp(witness, order) != RLC_LT)
        RLC_THROW(ERR_NO_VALID);
      ec_read_bin(statement, record+HOST_STATEMENT_OFFSET, 33);
      ec_read_bin(public_key->pk, record+HOST_JOINT_KEY_OFFSET, 33);
      if (ec_is_infty(statement) || ec_is_infty(public_key->pk) ||
          !ec_on_curve(statement) || !ec_on_curve(public_key->pk))
        RLC_THROW(ERR_NO_VALID);
      ec_write_bin(canonical, 33, statement, 1);
      if (memcmp(canonical, record+HOST_STATEMENT_OFFSET, 33)) RLC_THROW(ERR_NO_VALID);
      ec_write_bin(canonical, 33, public_key->pk, 1);
      if (memcmp(canonical, record+HOST_JOINT_KEY_OFFSET, 33)) RLC_THROW(ERR_NO_VALID);
      ec_mul_gen(computed, witness);
      if (ec_cmp(computed, statement) != RLC_EQ) RLC_THROW(ERR_NO_VALID);
      bn_read_bin(signature->e, record+HOST_CHALLENGE_OFFSET, 32);
      bn_read_bin(signature->s, record+HOST_SCALAR_OFFSET, 32);
      if (bn_cmp(signature->e, order) != RLC_LT ||
          bn_cmp(signature->s, order) != RLC_LT) RLC_THROW(ERR_NO_VALID);
      if (adaptor_schnorr_preverify(signature,
              record+HOST_TX_DIGEST_OFFSET, 32, statement, public_key) != 1)
        RLC_THROW(ERR_NO_VALID);
      bn_copy(saved, signature->s);
      /* AE uses s=r-e*x. Adapt adds w; extraction subtracts the pre-scalar. */
      bn_add(signature->s, signature->s, witness);
      bn_mod(signature->s, signature->s, order);
      if (adaptor_schnorr_preverify(signature,
              record+HOST_TX_DIGEST_OFFSET, 32, infinity, public_key) != 1)
        RLC_THROW(ERR_NO_VALID);
      bn_sub(extracted, signature->s, saved); bn_mod(extracted, extracted, order);
      ec_mul_gen(computed, extracted);
      if (bn_cmp(extracted, witness) != RLC_EQ || ec_cmp(computed, statement) != RLC_EQ)
        RLC_THROW(ERR_NO_VALID);
      if (i == 0) {
        if (host_ledger_spend_at(withdraw_ledger,i,signature,99) ||
            !host_ledger_spend_at(withdraw_ledger,i,signature,100) ||
            host_ledger_spend_at(withdraw_ledger,i,signature,100)) RLC_THROW(ERR_NO_VALID);
        bn_copy(signature->s,saved);
        bn_zero(extracted);
        if (!host_ledger_extract_withdrawal(withdraw_ledger,signature,statement,extracted) ||
            bn_cmp(extracted,witness)!=RLC_EQ) RLC_THROW(ERR_NO_VALID);
      } else if (i >= n) {
        uint64_t deadline;
        if (!host_relock_deadline(&schedule,i-n+1,&deadline) ||
            host_ledger_spend(relock_ledger,i,signature) ||
            host_ledger_spend_at(relock_ledger,i,signature,deadline-1) ||
            host_ledger_level(relock_ledger)!=i-n ||
            !host_ledger_spend_at(relock_ledger,i,signature,deadline) ||
            host_ledger_spend_at(relock_ledger,i,signature,deadline)) RLC_THROW(ERR_NO_VALID);
      }
    }
    if (host_ledger_state(withdraw_ledger) != HOST_WITHDRAWN ||
        host_ledger_state(relock_ledger) != HOST_LOCKED ||
        host_ledger_level(relock_ledger) != n-1) RLC_THROW(ERR_NO_VALID);
    if (refund_fd>=0) {
      uint8_t receipt[104];
      if (!file_size(refund_fd,sizeof(receipt)) ||
          exact_read(refund_fd,receipt,sizeof(receipt),0)!=RLC_OK ||
          memcmp(receipt,"OASISR01",8) || memcmp(receipt+8,refund_digest,32))
        RLC_THROW(ERR_NO_VALID);
      bn_read_bin(signature->e,receipt+40,32); bn_read_bin(signature->s,receipt+72,32);
      if (bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT ||
          host_ledger_refund_at(relock_ledger,signature,schedule.refund_ns-1) ||
          !host_ledger_refund_at(relock_ledger,signature,schedule.refund_ns) ||
          host_ledger_state(relock_ledger)!=HOST_REFUNDED ||
          host_ledger_refund_at(relock_ledger,signature,schedule.refund_ns))
        RLC_THROW(ERR_NO_VALID);
    }
    status = RLC_OK;
  } RLC_CATCH_ANY { status = RLC_ERR; }
  RLC_FINALLY {
    if (!funded_withdraw) host_ledger_destroy(withdraw_ledger);
    if (!funded_relock) host_ledger_destroy(relock_ledger);
    for (i = 0; i < initialized_keys; i++) ec_free(keys[i]);
    if (witness != NULL) bn_zero(witness);
    if (extracted != NULL) bn_zero(extracted);
    bn_free(order); bn_free(witness); bn_free(extracted); bn_free(saved);
    ec_free(statement); ec_free(computed); ec_free(infinity);
    if (signature != NULL) schnorr_signature_free(signature);
    if (public_key != NULL) ec_public_key_free(public_key);
    memzero(secret, sizeof(secret));
  }
  if (status == RLC_OK)
    printf("{\"verified_items\":%u,\"host_postprocess_ns\":%lld,"
           "\"live_presignature_handoff\":true,\"signed_ledger_paths_checked\":true,"
           "\"accepted_withdrawal_extraction\":true,"
           "\"retained_funded_ledger\":%s,"
           "\"timed_ledger_paths_checked\":true,\"ledger_clock\":\"controlled_fixture\","
           "\"live_refund_checked\":%s}\n", count, bench_monotonic_ns()-started,
           funded_withdraw && funded_relock ? "true" : "false",
           refund_fd>=0 ? "true" : "false");
  return status;
}

/* Two separate alternative ledger paths share the same admitted lock. They
 * represent withdrawal versus re-lock/refund, never two spends of one asset. */
static host_ledger *fund_registry(unsigned count,int registry_fd,int wallet_fd,int handoff_fd) {
  uint8_t registry[108+HOST_REGISTRY_RECORD_BYTES*255],header[104],digests[32*255];
  uint8_t refund[32],lock[32],amount[32]={0};
  ec_t keys[255],owner,infinity;
  ec_secret_key_t wallet;
  schnorr_signature_t signature;
  host_ledger *ledger=NULL;
  unsigned initialized=0,n=(count+1)/2;
  int status=RLC_ERR;
  int seals=fcntl(registry_fd,F_GET_SEALS),required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  if (count<5 || count>255 || !(count&1) ||
      seals<0 || (seals&required)!=required ||
      !file_size(registry_fd,108+HOST_REGISTRY_RECORD_BYTES*count) ||
      exact_read(registry_fd,registry,108+HOST_REGISTRY_RECORD_BYTES*count,0)!=RLC_OK ||
      memcmp(registry,HOST_REGISTRY_MAGIC,8) || registry[8] || registry[9] || registry[10] ||
      registry[11]!=count || !file_size(handoff_fd,0)) return NULL;
  ec_null(owner); ec_null(infinity); ec_secret_key_null(wallet); schnorr_signature_null(signature);
  RLC_TRY {
    ec_new(owner); ec_new(infinity); ec_set_infty(infinity);
    ec_secret_key_new(wallet); schnorr_signature_new(signature);
    if (host_read_key(wallet_fd,wallet->sk,owner)!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<count;i++) {
      ec_null(keys[i]); ec_new(keys[i]); initialized++;
      ec_read_bin(keys[i],registry+108+HOST_REGISTRY_RECORD_BYTES*i+
                  HOST_JOINT_KEY_OFFSET,33);
      memcpy(digests+32*i,registry+108+HOST_REGISTRY_RECORD_BYTES*i+
             HOST_TX_DIGEST_OFFSET,32);
    }
    memcpy(header,HOST_HANDOFF_MAGIC,8); memcpy(header+8,registry+12,96); amount[31]=1;
    if (host_fixture_refund_digest(refund,header)!=RLC_OK ||
        !host_ledger_lock_digest(lock,registry+12,owner,keys[0],amount)) RLC_THROW(ERR_NO_VALID);
    ledger=host_ledger_create_unfunded(n,digests,keys,refund,100,15,2,registry+12,owner,amount);
    if (!ledger || adaptor_schnorr_sign(signature,lock,32,infinity,wallet)!=RLC_OK ||
        !host_ledger_lock_at(ledger,signature,100))
      RLC_THROW(ERR_NO_VALID);
    bn_zero(wallet->sk);
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i=0;i<initialized;i++) ec_free(keys[i]);
    ec_free(owner); ec_free(infinity);
    if (wallet!=NULL) { bn_zero(wallet->sk); ec_secret_key_free(wallet); }
    if (signature!=NULL) schnorr_signature_free(signature);
  }
  if (status!=RLC_OK) { host_ledger_destroy(ledger); return NULL; }
  return ledger;
}

static int registry_matches(unsigned count,int registry_fd,int handoff_fd) {
  uint8_t registry[108+HOST_REGISTRY_RECORD_BYTES*255],header[104],
      record[HOST_REGISTRY_RECORD_BYTES];
  if (count<5 || count>255 || !(count&1) ||
      !file_size(registry_fd,108+HOST_REGISTRY_RECORD_BYTES*count) ||
      exact_read(registry_fd,registry,108+HOST_REGISTRY_RECORD_BYTES*count,0)!=RLC_OK ||
      !file_size(handoff_fd,HOST_HEADER_BYTES+HOST_RECORD_BYTES*count) ||
      exact_read(handoff_fd,header,104,0)!=RLC_OK ||
      memcmp(header,HOST_HANDOFF_MAGIC,8) ||
      memcmp(header+8,registry+12,96)) return 0;
  for (unsigned i=0;i<count;i++) {
    if (exact_read(handoff_fd,record,HOST_REGISTRY_RECORD_BYTES,
          HOST_HEADER_BYTES+HOST_RECORD_BYTES*i)!=RLC_OK ||
        memcmp(record,registry+108+HOST_REGISTRY_RECORD_BYTES*i,
               HOST_REGISTRY_RECORD_BYTES)) return 0;
  }
  return 1;
}

static int funded_check(unsigned count,int registry_fd,int wallet_fd,int handoff_fd,
    int witness_fd,int refund_fd) {
  host_ledger *withdraw=fund_registry(count,registry_fd,wallet_fd,handoff_fd);
  host_ledger *relock=fund_registry(count,registry_fd,wallet_fd,handoff_fd);
  int status=RLC_ERR;
  if (withdraw && relock) {
    puts("LOCK_ACCEPTED"); fflush(stdout);
    if (getchar()=='C' && registry_matches(count,registry_fd,handoff_fd))
      status=check(count,handoff_fd,witness_fd,refund_fd,withdraw,relock);
  }
  host_ledger_destroy(withdraw); host_ledger_destroy(relock);
  return status;
}

/* Inputs: incoming/outgoing registry, wallet, handoff, witness, then identifier. */
static int funded_recovery(unsigned count,unsigned level,const int fd[9]) {
  host_ledger *incoming=fund_registry(count,fd[0],fd[2],fd[4]);
  host_ledger *outgoing=fund_registry(count,fd[1],fd[3],fd[5]);
  int status=RLC_ERR;
  if (incoming && outgoing) {
    puts("LOCK_ACCEPTED"); fflush(stdout);
    if (getchar()=='C' && registry_matches(count,fd[0],fd[4]) &&
        registry_matches(count,fd[1],fd[5])) {
      status=host_check_recovery_retained(count,level,fd[4],fd[5],fd[8],fd[6],fd[7],incoming,outgoing);
      if (status==RLC_OK && (host_ledger_state(incoming)!=HOST_WITHDRAWN ||
          host_ledger_state(outgoing)!=HOST_WITHDRAWN)) status=RLC_ERR;
    }
  }
  host_ledger_destroy(incoming); host_ledger_destroy(outgoing);
  return status;
}

static int funded_cycle_recovery(unsigned count,const int fd[128][5],int retry_test,int all_honest,int refund_cycle) {
  unsigned n=(count+1)/2;
  host_ledger *ledgers[128]={0};
  int handoffs[128],witnesses[128],identifiers[128],status=RLC_ERR;
  for (unsigned i=0;i<n;i++) {
    ledgers[i]=fund_registry(count,fd[i][0],fd[i][1],fd[i][2]);
    if (!ledgers[i]) goto cleanup;
    handoffs[i]=fd[i][2]; witnesses[i]=fd[i][3]; identifiers[i]=fd[i][4];
  }
  puts("LOCK_ACCEPTED"); fflush(stdout);
  int command=getchar();
  if (command=='A') {
    unsigned locked=0,withdrawn=0,refunded=0;
    for (unsigned i=0;i<n;i++) {
      host_asset_state state=host_ledger_state(ledgers[i]);
      locked+=state==HOST_LOCKED;
      withdrawn+=state==HOST_WITHDRAWN;
      refunded+=state==HOST_REFUNDED;
    }
    printf("{\"retained_cycle_abort_observed\":true,\"locked_arcs\":%u,"
           "\"withdrawn_arcs\":%u,\"refunded_arcs\":%u,"
           "\"automatic_refund_performed\":false}\n",locked,withdrawn,refunded);
    status=RLC_OK;
    goto cleanup;
  }
  if (command!='C') goto cleanup;
  for (unsigned i=0;i<n;i++) if (!registry_matches(count,fd[i][0],fd[i][2])) goto cleanup;
  if (refund_cycle) {
    for (unsigned i=0;i<n;i++)
      if (host_refund_retained(count,handoffs[i],witnesses[i],fd[i][4],ledgers[i])!=RLC_OK)
        goto cleanup;
    printf("{\"retained_cycle_refund\":true,\"refunded_arcs\":%u,"
           "\"withdrawn_arcs\":0,\"ledger_clock\":\"controlled_fixture\","
           "\"full_lifecycle\":false}\n",n);
    status=RLC_OK;
    goto cleanup;
  }
  if (retry_test && all_honest) {
    int saved=witnesses[n-1]; witnesses[n-1]=-1;
    int rejected=host_withdraw_cycle(count,handoffs,witnesses,ledgers);
    witnesses[n-1]=saved;
    if (rejected==RLC_OK || host_ledger_state(ledgers[n-1])!=HOST_LOCKED) goto cleanup;
    for (unsigned i=0;i<n-1;i++)
      if (host_ledger_state(ledgers[i])!=HOST_WITHDRAWN || host_ledger_level(ledgers[i])!=0)
        goto cleanup;
  } else if (retry_test) {
    int saved=witnesses[1]; witnesses[1]=-1;
    int rejected=host_recover_cycle(count,handoffs,witnesses,identifiers,ledgers);
    witnesses[1]=saved;
    if (rejected==RLC_OK || host_ledger_state(ledgers[0])!=HOST_WITHDRAWN ||
        host_ledger_state(ledgers[1])!=HOST_LOCKED ||
        host_ledger_state(ledgers[n-1])!=HOST_WITHDRAWN) goto cleanup;
    /* Let the final arc accept its earlier re-locks, then fail on the last
     * delayed witness. The next invocation must keep that address level. */
    unsigned char values[8+255*32];
    size_t size=8+count*32;
    int interrupted=memfd_create("oasis-cycle-retry-witness",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (interrupted<0) goto cleanup;
    int ready=exact_read(saved,values,size,0)==RLC_OK;
    memset(values+size-32,0,32);
    if (!ready || write(interrupted,values,size)!=(ssize_t)size ||
        fcntl(interrupted,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK)<0) {
      memzero(values,sizeof(values)); close(interrupted); goto cleanup;
    }
    memzero(values,sizeof(values));
    witnesses[1]=interrupted;
    rejected=host_recover_cycle(count,handoffs,witnesses,identifiers,ledgers);
    witnesses[1]=saved; close(interrupted);
    if (rejected==RLC_OK || host_ledger_state(ledgers[1])!=HOST_LOCKED ||
        host_ledger_level(ledgers[1])!=n-2) goto cleanup;
  }
  status=all_honest ? host_withdraw_cycle(count,handoffs,witnesses,ledgers) :
      host_recover_cycle(count,handoffs,witnesses,identifiers,ledgers);
cleanup:
  for (unsigned i=0;i<n;i++) host_ledger_destroy(ledgers[i]);
  return status;
}

static int key_public(unsigned count,int address_keys,int key_fd,int public_fd) {
  bn_t secret; ec_t point;
  uint8_t encoded[41];
  int status=RLC_ERR;
  if (!file_size(public_fd,0) || key_fd==public_fd) return RLC_ERR;
  bn_null(secret); ec_null(point);
  RLC_TRY {
    bn_new(secret); ec_new(point);
    for (unsigned i=0;i<count;i++) {
      if ((address_keys ? host_read_address_key(key_fd,count,i,secret,point) :
           host_read_key(key_fd,secret,point))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
      if (address_keys==2) {
        uint8_t preparation[32]={0},proof[BENCH_KEY_OWNERSHIP_PROOF_BYTES];
        if (host_address_key_prove(proof,secret,point,preparation,count,i,
              BENCH_KEY_ROLE_INITIATOR,0,1)!=RLC_OK ||
            host_address_key_verify(proof,point,preparation,count,i,
              BENCH_KEY_ROLE_INITIATOR,0,1)!=RLC_OK ||
            host_address_key_verify(proof,point,preparation,count,(i+1)%count,
              BENCH_KEY_ROLE_INITIATOR,0,1)==RLC_OK ||
            host_address_key_verify(proof,point,preparation,count,i,
              BENCH_KEY_ROLE_RESPONDER,0,1)==RLC_OK ||
            host_address_key_verify(proof,point,preparation,count,i,
              BENCH_KEY_ROLE_INITIATOR,1,1)==RLC_OK ||
            host_address_key_verify(proof,point,preparation,count,i,
              BENCH_KEY_ROLE_INITIATOR,0,2)==RLC_OK) RLC_THROW(ERR_NO_VALID);
        preparation[0]=1;
        if (host_address_key_verify(proof,point,preparation,count,i,
              BENCH_KEY_ROLE_INITIATOR,0,1)==RLC_OK) RLC_THROW(ERR_NO_VALID);
      }
      memcpy(encoded,HOST_PUBLIC_MAGIC,8); ec_write_bin(encoded+8,33,point,1);
      if (exact_write(public_fd,encoded+(i ? 8 : 0),i ? 33 : 41)!=RLC_OK)
        RLC_THROW(ERR_NO_VALID);
    }
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (secret!=NULL) bn_zero(secret);
    bn_free(secret); ec_free(point);
  }
  if (status!=RLC_OK) (void)ftruncate(public_fd,0);
  return status;
}

/* Public registry produced before signing from the same canonical constructor.
 * No pre-signature slots exist in this format, so it cannot impersonate a
 * completed handoff. The local host must admit this registry before funding. */
static int prepare_registry(int argc,char **argv) {
  bench_options_t options;
  bench_transcript_t transcript={0};
  ec_t unused;
  int status=1;
  if (bench_parse_options(argc,argv,&options)!=RLC_OK ||
      options.context_participants<3 || !options.host_statements[0] ||
      options.host_address_keys_fd<3 || options.host_client_keys_fd<3 ||
      options.host_server_keys_fd<3 || !file_size(options.host_output_fd,0)) return 2;
  if (init()!=RLC_OK) return 1;
  ec_null(unused);
  RLC_TRY {
    ec_new(unused); ec_set_infty(unused);
    if (host_admit_address_keys(&options,BENCH_KEY_ROLE_INITIATOR)!=RLC_OK ||
        bench_transcript_init(&transcript,&options,unused,unused)!=RLC_OK)
      RLC_THROW(ERR_NO_VALID);
    uint8_t header[108]={0},record[HOST_REGISTRY_RECORD_BYTES];
    memcpy(header,HOST_REGISTRY_MAGIC,8);
    header[8]=(uint8_t)(options.count>>24); header[9]=(uint8_t)(options.count>>16);
    header[10]=(uint8_t)(options.count>>8); header[11]=(uint8_t)options.count;
    memcpy(header+12,transcript.context_digest,32);
    memcpy(header+44,transcript.parent_sid,32); memcpy(header+76,transcript.batch_digest,32);
    if (exact_write(options.host_output_fd,header,sizeof(header))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<options.count;i++) {
      memcpy(record+HOST_TX_DIGEST_OFFSET,
             transcript.message_digests+32*i,32);
      memcpy(record+HOST_ITEM_DIGEST_OFFSET,
             transcript.item_digests+32*i,32);
      ec_write_bin(record+HOST_STATEMENT_OFFSET,33,transcript.statements[i],1);
      ec_write_bin(record+HOST_JOINT_KEY_OFFSET,33,
                   transcript.joint_public_keys[i],1);
      if (exact_write(options.host_output_fd,record,sizeof(record))!=RLC_OK) RLC_THROW(ERR_NO_VALID);
    }
    status=0;
  } RLC_CATCH_ANY { status=1; }
  RLC_FINALLY {
    bench_transcript_free(&transcript); host_release_address_keys(&options); ec_free(unused);
  }
  if (status && ftruncate(options.host_output_fd,0)) status=1;
  clean(); return status;
}

int main(int argc, char **argv) {
  if (argc==9 && !strcmp(argv[1],"recover-arc")) {
    unsigned long v[7];
    for (unsigned i=0;i<7;i++) {
      char *end; errno=0; v[i]=strtoul(argv[i+2],&end,10);
      if (errno || *end || end==argv[i+2] || v[i]>1048575 || (i>=2 && v[i]<3)) return 2;
    }
    if (init()!=RLC_OK) return 1;
    int result=host_check_recovery((unsigned)v[0],(unsigned)v[1],(int)v[2],(int)v[3],
        (int)v[4],(int)v[5],(int)v[6]);
    clean(); return result==RLC_OK ? 0 : 1;
  }
  if (argc>1 && !strcmp(argv[1],"prepare-registry")) return prepare_registry(argc-1,argv+1);
  if (argc>2 && (!strcmp(argv[1],"funded-cycle-recovery") ||
      !strcmp(argv[1],"funded-cycle-refund") ||
      !strcmp(argv[1],"funded-cycle-withdrawal") ||
      !strcmp(argv[1],"funded-cycle-withdrawal-retry-test") ||
      !strcmp(argv[1],"funded-cycle-recovery-retry-test"))) {
    char *end; errno=0; unsigned long count=strtoul(argv[2],&end,10);
    if (errno || *end || end==argv[2] || count<5 || count>255 || !(count&1)) return 2;
    unsigned n=(count+1)/2; int fd[128][5];
    if (argc!=3+(int)(5*n)) return 2;
    for (unsigned i=0;i<5*n;i++) {
      errno=0; unsigned long value=strtoul(argv[3+i],&end,10);
      if (errno || *end || end==argv[3+i] || value<3 || value>1048575) return 2;
      fd[i/5][i%5]=(int)value;
    }
    if (init()!=RLC_OK) return 1;
    int result=funded_cycle_recovery((unsigned)count,fd,
        !strcmp(argv[1],"funded-cycle-recovery-retry-test") ||
            !strcmp(argv[1],"funded-cycle-withdrawal-retry-test"),
        !strcmp(argv[1],"funded-cycle-withdrawal") ||
            !strcmp(argv[1],"funded-cycle-withdrawal-retry-test"),
        !strcmp(argv[1],"funded-cycle-refund"));
    clean(); return result==RLC_OK ? 0 : 1;
  }
  if (argc==13 && !strcmp(argv[1],"funded-recovery")) {
    unsigned long v[11]; int fd[9];
    for (unsigned i=0;i<11;i++) {
      char *end; errno=0; v[i]=strtoul(argv[i+2],&end,10);
      if (errno || *end || end==argv[i+2] || v[i]>1048575 || (i>=2 && v[i]<3)) return 2;
      if (i>=2) fd[i-2]=(int)v[i];
    }
    if (v[0]<5 || v[0]>255 || !(v[0]&1) || v[1]>=(v[0]+1)/2-1) return 2;
    if (init()!=RLC_OK) return 1;
    int result=funded_recovery((unsigned)v[0],(unsigned)v[1],fd);
    clean(); return result==RLC_OK ? 0 : 1;
  }
  if (argc==8 && !strcmp(argv[1],"funded-check")) {
    unsigned long v[6];
    for (unsigned i=0;i<6;i++) {
      char *end; errno=0; v[i]=strtoul(argv[i+2],&end,10);
      if (errno || *end || end==argv[i+2] || v[i]>1048575 || v[i]<3) return 2;
    }
    if (init()!=RLC_OK) return 1;
    int result=funded_check((unsigned)v[0],(int)v[1],(int)v[2],(int)v[3],(int)v[4],(int)v[5]);
    clean(); return result==RLC_OK ? 0 : 1;
  }
  unsigned long values[3];
  char *end;
  unsigned i;
  int status;
  uint8_t preparation[32]={0};
  unsigned long pair=0;
  bench_key_role_t role=BENCH_KEY_ROLE_INITIATOR;
  int refund_fd=-1,participant_fd=-1;
  if (argc==6 && !strcmp(argv[1],"prepare-participants")) {
    errno=0; unsigned long fd=strtoul(argv[5],&end,10);
    if (errno || end==argv[5] || *end || fd<3 || fd>1048575) return 2;
    participant_fd=(int)fd;
  }
  if (argc==6 && !strcmp(argv[1],"check-refund")) {
    errno=0; unsigned long fd=strtoul(argv[5],&end,10);
    if (errno || end==argv[5] || *end || fd<3 || fd>1048575) return 2;
    refund_fd=(int)fd;
  } else if (participant_fd<0 && argc != 5 && !(argc==8 && !strcmp(argv[1],"address-bundle"))) return 2;
  if (argc==8) {
    if (strlen(argv[5])!=64) return 2;
    for (i=0;i<32;i++) {
      unsigned value=0;
      for (unsigned j=0;j<2;j++) {
        char c=argv[5][2*i+j];
        unsigned digit=c>='0' && c<='9' ? (unsigned)(c-'0') :
                       c>='a' && c<='f' ? (unsigned)(c-'a'+10) : 16;
        if (digit>15) return 2;
        value=16*value+digit;
      }
      preparation[i]=(uint8_t)value;
    }
    if (!strcmp(argv[6],"responder")) role=BENCH_KEY_ROLE_RESPONDER;
    else if (strcmp(argv[6],"initiator")) return 2;
    errno=0; pair=strtoul(argv[7],&end,10);
    if (errno || *end || end==argv[7] || pair>UINT32_MAX) return 2;
  }
  for (i = 0; i < 3; i++) {
    errno = 0; values[i] = strtoul(argv[i+2], &end, 10);
    if (errno || *end || end == argv[i+2] || values[i] > 1048575) return 2;
  }
  if (values[0] < 1 || values[0] > BENCH_MAX_ITEMS ||
      values[1] < 3 || values[2] < 3) return 2;
  if (init() != RLC_OK) return 1;
  if (!strcmp(argv[1],"address-bundle") && argc==8)
    status=host_write_address_public((int)values[2],(int)values[1],(unsigned)values[0],
                                    preparation,role,pair,1);
  else if ((!strcmp(argv[1], "prepare") || participant_fd>=0) && values[0] >= 3 && values[0] <= 128)
    status = prepare((unsigned)values[0], (int)values[1], (int)values[2],participant_fd);
  else if (!strcmp(argv[1],"key-public") && values[0]==1)
    status=key_public(1,0,(int)values[1],(int)values[2]);
  else if (!strcmp(argv[1],"address-public") && values[0]>=3 && values[0]<=128)
    status=key_public((unsigned)values[0],1,(int)values[1],(int)values[2]);
  else if (!strcmp(argv[1],"test-address-proofs") && values[0]>=3 && values[0]<=128)
    status=key_public((unsigned)values[0],2,(int)values[1],(int)values[2]);
  else if (!strcmp(argv[1],"test-address-bundle-write")) {
    uint8_t preparation[32]={0};
    status=host_write_address_public((int)values[2],(int)values[1],(unsigned)values[0],
        preparation,BENCH_KEY_ROLE_INITIATOR,0,1);
  } else if (!strcmp(argv[1],"test-address-bundle-read")) {
    uint8_t preparation[32]={0};
    ec_t point; ec_null(point); status=RLC_ERR;
    RLC_TRY {
      ec_new(point);
      status=host_read_address_public((int)values[1],(unsigned)values[0],0,point,
          preparation,BENCH_KEY_ROLE_INITIATOR,0,1);
    } RLC_CATCH_ANY { status=RLC_ERR; }
    RLC_FINALLY { ec_free(point); }
  }
  else if (!strcmp(argv[1], "check") || (refund_fd>=0 && !strcmp(argv[1],"check-refund")))
    status = check((unsigned)values[0], (int)values[1], (int)values[2],refund_fd,NULL,NULL);
  else status = RLC_ERR;
  clean();
  return status == RLC_OK ? 0 : 1;
}
