#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "host_handoff.h"
#include "host_ledger.h"
#include "host_witness.h"
#include "host_recovery.h"

int host_recover_into(host_ledger *incoming,const host_ledger *outgoing,
    schnorr_signature_t source_pre,const ec_t source_statement,
    schnorr_signature_t destination_pre,const ec_t destination_statement,
    const bn_t local_identifier,uint64_t now_ns) {
  if (!incoming || !outgoing || incoming==outgoing || !source_pre || !destination_pre ||
      host_ledger_state(outgoing)!=HOST_WITHDRAWN ||
      host_ledger_state(incoming)!=HOST_LOCKED ||
      host_ledger_level(incoming)!=host_ledger_level(outgoing)+1) return 0;
  bn_t extracted,recovered,order;
  schnorr_signature_t final;
  int valid=0;
  bn_null(extracted); bn_null(recovered); bn_null(order); schnorr_signature_null(final);
  RLC_TRY {
    bn_new(extracted); bn_new(recovered); bn_new(order); schnorr_signature_new(final);
    ec_curve_get_ord(order);
    if (bn_sign(destination_pre->e)==RLC_NEG || bn_sign(destination_pre->s)==RLC_NEG ||
        bn_cmp(destination_pre->e,order)!=RLC_LT || bn_cmp(destination_pre->s,order)!=RLC_LT ||
        !host_ledger_extract_withdrawal(outgoing,source_pre,source_statement,extracted) ||
        !host_witness_advance(extracted,source_statement,local_identifier,
            destination_statement,recovered)) RLC_THROW(ERR_NO_VALID);
    bn_copy(final->e,destination_pre->e);
    bn_add(final->s,destination_pre->s,recovered); bn_mod(final->s,final->s,order);
    valid=host_ledger_spend_at(incoming,host_ledger_level(incoming),final,now_ns);
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY {
    if (extracted!=NULL) bn_zero(extracted);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(extracted); bn_free(recovered); bn_free(order);
    if (final!=NULL) schnorr_signature_free(final);
  }
  return valid;
}

typedef struct {
  unsigned n,initialized;
  int owns_ledger;
  unsigned char header[HOST_HEADER_BYTES],records[255*HOST_RECORD_BYTES],digests[255*32];
  ec_t keys[255];
  host_ledger *ledger;
  host_schedule schedule;
} recovery_arc;

static int sealed_size(int fd,size_t size) {
  struct stat st;
  int seals=fcntl(fd,F_GET_SEALS),required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK;
  return host_memory_fd(fd) && seals>=0 && (seals&required)==required &&
      !fstat(fd,&st) && st.st_size==(off_t)size;
}

static void destroy_arc(recovery_arc *arc) {
  if (!arc) return;
  if (arc->owns_ledger) host_ledger_destroy(arc->ledger);
  for (unsigned i=0;i<arc->initialized;i++) ec_free(arc->keys[i]);
  free(arc);
}

static recovery_arc *load_arc(int fd,unsigned count,host_ledger *retained) {
  if (!sealed_size(fd,HOST_HEADER_BYTES+HOST_RECORD_BYTES*count)) return NULL;
  recovery_arc *arc=calloc(1,sizeof(*arc));
  if (!arc) return NULL;
  int valid=0;
  arc->n=(count+1)/2;
  RLC_TRY {
    unsigned char refund[32];
    if (pread(fd,arc->header,HOST_HEADER_BYTES,0)!=HOST_HEADER_BYTES ||
        memcmp(arc->header,HOST_HANDOFF_MAGIC,8) ||
        pread(fd,arc->records,HOST_RECORD_BYTES*count,HOST_HEADER_BYTES) !=
            (ssize_t)(HOST_RECORD_BYTES*count)) RLC_THROW(ERR_NO_VALID);
    for (unsigned i=0;i<count;i++) {
      ec_null(arc->keys[i]); ec_new(arc->keys[i]); arc->initialized++;
      ec_read_bin(arc->keys[i],arc->records+HOST_RECORD_BYTES*i+
                  HOST_JOINT_KEY_OFFSET,33);
      memcpy(arc->digests+32*i,arc->records+HOST_RECORD_BYTES*i+
             HOST_TX_DIGEST_OFFSET,32);
    }
    if (host_fixture_refund_digest(refund,arc->header)!=RLC_OK ||
        !host_schedule_init(&arc->schedule,arc->n,100,15,2)) RLC_THROW(ERR_NO_VALID);
    arc->owns_ledger=retained==NULL;
    arc->ledger=retained ? retained :
        host_ledger_create_timed(arc->n,arc->digests,arc->keys,refund,100,15,2);
    if (!arc->ledger) RLC_THROW(ERR_NO_VALID);
    valid=1;
  } RLC_CATCH_ANY { valid=0; }
  if (!valid) { destroy_arc(arc); return NULL; }
  return arc;
}

static int read_witness(int fd,unsigned count,unsigned ordinal,bn_t output,const bn_t order) {
  unsigned char magic[8],value[32];
  int valid=0;
  if (ordinal>=count || !sealed_size(fd,8+32*count) || pread(fd,magic,8,0)!=8 ||
      memcmp(magic,"OASISW01",8) || pread(fd,value,32,8+32*ordinal)!=32) return 0;
  bn_read_bin(output,value,32); memzero(value,sizeof(value));
  valid=!bn_is_zero(output) && bn_cmp(output,order)==RLC_LT;
  return valid;
}

static int adapt_and_spend(recovery_arc *arc,unsigned ordinal,const bn_t witness,
    schnorr_signature_t signature,ec_t statement,const bn_t order,uint64_t now) {
  unsigned char *record=arc->records+HOST_RECORD_BYTES*ordinal;
  ec_public_key_t key;
  int valid=0;
  ec_public_key_null(key);
  RLC_TRY {
    ec_public_key_new(key); ec_copy(key->pk,arc->keys[ordinal]);
    ec_read_bin(statement,record+HOST_STATEMENT_OFFSET,33);
    bn_read_bin(signature->e,record+HOST_CHALLENGE_OFFSET,32);
    bn_read_bin(signature->s,record+HOST_SCALAR_OFFSET,32);
    if (bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT ||
        adaptor_schnorr_preverify(signature,record+HOST_TX_DIGEST_OFFSET,32,
                                  statement,key)!=1) RLC_THROW(ERR_NO_VALID);
    bn_add(signature->s,signature->s,witness); bn_mod(signature->s,signature->s,order);
    valid=host_ledger_spend_at(arc->ledger,ordinal,signature,now);
  } RLC_CATCH_ANY { valid=0; }
  RLC_FINALLY { if (key!=NULL) ec_public_key_free(key); }
  return valid;
}

static int relock_to(recovery_arc *arc,unsigned level,int witnesses,bn_t value,
    schnorr_signature_t signature,ec_t statement,const bn_t order) {
  if (host_ledger_state(arc->ledger)!=HOST_LOCKED ||
      host_ledger_level(arc->ledger)>level || level>=arc->n) return 0;
  for (unsigned j=host_ledger_level(arc->ledger);j<level;j++) {
    uint64_t now;
    if (!read_witness(witnesses,2*arc->n-1,arc->n+j,value,order) ||
        !host_relock_deadline(&arc->schedule,j+1,&now) ||
        !adapt_and_spend(arc,arc->n+j,value,signature,statement,order,now)) return 0;
  }
  return 1;
}

int host_refund_retained(unsigned count,int handoff,int witnesses,int receipt,
    host_ledger *ledger) {
  if (count<5 || count>255 || !(count&1) || !ledger ||
      !sealed_size(receipt,104) ||
      host_ledger_state(ledger)!=HOST_LOCKED) return RLC_ERR;
  recovery_arc *arc=load_arc(handoff,count,ledger);
  if (!arc) return RLC_ERR;
  bn_t value,order;
  ec_t statement;
  schnorr_signature_t signature;
  unsigned char encoded[105],digest[32];
  ec_public_key_t refund_key;
  ec_public_key_null(refund_key);
  int status=RLC_ERR;
  bn_null(value); bn_null(order); ec_null(statement); schnorr_signature_null(signature);
  RLC_TRY {
    bn_new(value); bn_new(order); ec_curve_get_ord(order);
    ec_new(statement); schnorr_signature_new(signature);
    ec_public_key_new(refund_key);
    ec_copy(refund_key->pk,arc->keys[arc->n-1]);
    if (pread(receipt,encoded,sizeof(encoded),0)!=104 ||
        memcmp(encoded,"OASISR01",8) ||
        host_fixture_refund_digest(digest,arc->header)!=RLC_OK ||
        memcmp(encoded+8,digest,32)) RLC_THROW(ERR_NO_VALID);
    bn_read_bin(signature->e,encoded+40,32);
    bn_read_bin(signature->s,encoded+72,32);
    ec_set_infty(statement);
    if (bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT ||
        adaptor_schnorr_preverify(signature,digest,32,statement,refund_key)!=1)
      RLC_THROW(ERR_NO_VALID);
    if (!relock_to(arc,arc->n-1,witnesses,value,signature,statement,order))
      RLC_THROW(ERR_NO_VALID);
    bn_read_bin(signature->e,encoded+40,32);
    bn_read_bin(signature->s,encoded+72,32);
    if (bn_cmp(signature->e,order)!=RLC_LT || bn_cmp(signature->s,order)!=RLC_LT ||
        !host_ledger_refund_at(ledger,signature,arc->schedule.refund_ns) ||
        host_ledger_state(ledger)!=HOST_REFUNDED) RLC_THROW(ERR_NO_VALID);
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    if (value!=NULL) bn_zero(value);
    bn_free(value); bn_free(order); ec_free(statement);
    if (signature!=NULL) schnorr_signature_free(signature);
    destroy_arc(arc);
    if (refund_key!=NULL) ec_public_key_free(refund_key);
  }
  return status;
}

static int check_recovery(unsigned count,unsigned level,int incoming_fd,int outgoing_fd,
    int identifier_fd,int incoming_witness_fd,int outgoing_witness_fd,
    host_ledger *retained_incoming,host_ledger *retained_outgoing) {
  if (count<5 || count>255 || !(count&1) || level>=(count+1)/2-1) return RLC_ERR;
  recovery_arc *incoming=load_arc(incoming_fd,count,retained_incoming),
      *outgoing=load_arc(outgoing_fd,count,retained_outgoing);
  bn_t value,extracted,identifier,recovered,order;
  ec_t source,destination,identifier_point;
  schnorr_signature_t signature,source_pre;
  int status=RLC_ERR;
  bn_null(value); bn_null(extracted); bn_null(identifier); bn_null(recovered); bn_null(order);
  ec_null(source); ec_null(destination); ec_null(identifier_point); schnorr_signature_null(signature);
  schnorr_signature_null(source_pre);
  RLC_TRY {
    bn_new(value); bn_new(extracted); bn_new(identifier); bn_new(recovered); bn_new(order);
    ec_new(source); ec_new(destination); ec_new(identifier_point); schnorr_signature_new(signature);
    schnorr_signature_new(source_pre);
    ec_curve_get_ord(order);
    if (!incoming || !outgoing || host_read_key(identifier_fd,identifier,identifier_point)!=RLC_OK ||
        !relock_to(outgoing,level,outgoing_witness_fd,value,signature,source,order) ||
        !read_witness(outgoing_witness_fd,count,level,value,order)) RLC_THROW(ERR_NO_VALID);
    uint64_t source_time=100,destination_time;
    if (level && !host_relock_deadline(&outgoing->schedule,level,&source_time)) RLC_THROW(ERR_NO_VALID);
    if (!adapt_and_spend(outgoing,level,value,signature,source,order,source_time)) RLC_THROW(ERR_NO_VALID);
    const unsigned char *record=outgoing->records+HOST_RECORD_BYTES*level;
    bn_read_bin(signature->e,record+HOST_CHALLENGE_OFFSET,32);
    bn_read_bin(signature->s,record+HOST_SCALAR_OFFSET,32);
    bn_copy(source_pre->e,signature->e); bn_copy(source_pre->s,signature->s);
    if (!host_ledger_extract_withdrawal(outgoing->ledger,signature,source,extracted)) RLC_THROW(ERR_NO_VALID);
    ec_read_bin(destination,incoming->records+HOST_RECORD_BYTES*(level+1)+
                HOST_STATEMENT_OFFSET,33);
    if (!host_witness_advance(extracted,source,identifier,destination,recovered) ||
        !relock_to(incoming,level+1,incoming_witness_fd,value,signature,destination,order) ||
        !host_relock_deadline(&incoming->schedule,level+1,&destination_time)) RLC_THROW(ERR_NO_VALID);
    record=incoming->records+HOST_RECORD_BYTES*(level+1);
    bn_read_bin(signature->e,record+HOST_CHALLENGE_OFFSET,32);
    bn_read_bin(signature->s,record+HOST_SCALAR_OFFSET,32);
    ec_read_bin(destination,record+HOST_STATEMENT_OFFSET,33);
    bn_add_dig(signature->s,signature->s,1); bn_mod(signature->s,signature->s,order);
    if (host_recover_into(incoming->ledger,outgoing->ledger,source_pre,source,
            signature,destination,identifier,destination_time) ||
        host_ledger_state(incoming->ledger)!=HOST_LOCKED ||
        host_ledger_level(incoming->ledger)!=level+1) RLC_THROW(ERR_NO_VALID);
    bn_read_bin(signature->s,record+HOST_SCALAR_OFFSET,32);
    if (!host_recover_into(incoming->ledger,outgoing->ledger,source_pre,source,
            signature,destination,identifier,destination_time) ||
        host_ledger_state(incoming->ledger)!=HOST_WITHDRAWN ||
        host_recover_into(incoming->ledger,outgoing->ledger,source_pre,source,
            signature,destination,identifier,destination_time)) RLC_THROW(ERR_NO_VALID);
    printf("{\"observed_withdrawal_extraction\":true,\"cross_arc_recovery\":true,"
        "\"source_level\":%u,\"destination_level\":%u,\"full_lifecycle\":false}\n",level,level+1);
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    destroy_arc(incoming); destroy_arc(outgoing);
    if (value!=NULL) bn_zero(value);
    if (extracted!=NULL) bn_zero(extracted);
    if (identifier!=NULL) bn_zero(identifier);
    if (recovered!=NULL) bn_zero(recovered);
    bn_free(value); bn_free(extracted); bn_free(identifier); bn_free(recovered); bn_free(order);
    ec_free(source); ec_free(destination); ec_free(identifier_point);
    if (signature!=NULL) schnorr_signature_free(signature);
    if (source_pre!=NULL) schnorr_signature_free(source_pre);
  }
  return status;
}

int host_check_recovery(unsigned count,unsigned level,int incoming_fd,int outgoing_fd,
    int identifier_fd,int incoming_witness_fd,int outgoing_witness_fd) {
  return check_recovery(count,level,incoming_fd,outgoing_fd,identifier_fd,
      incoming_witness_fd,outgoing_witness_fd,NULL,NULL);
}

int host_check_recovery_retained(unsigned count,unsigned level,int incoming_fd,int outgoing_fd,
    int identifier_fd,int incoming_witness_fd,int outgoing_witness_fd,
    host_ledger *incoming,host_ledger *outgoing) {
  if (!incoming || !outgoing || incoming==outgoing ||
      host_ledger_state(incoming)!=HOST_LOCKED || host_ledger_state(outgoing)!=HOST_LOCKED ||
      host_ledger_level(incoming)!=0 || host_ledger_level(outgoing)!=0) return RLC_ERR;
  return check_recovery(count,level,incoming_fd,outgoing_fd,identifier_fd,
      incoming_witness_fd,outgoing_witness_fd,incoming,outgoing);
}

int host_withdraw_cycle(unsigned count,const int *handoffs,const int *witnesses,
    host_ledger **ledgers) {
  if (count<5 || count>255 || !(count&1) || !handoffs || !witnesses || !ledgers)
    return RLC_ERR;
  unsigned n=(count+1)/2;
  recovery_arc *arcs[128]={0};
  bn_t value,order;
  ec_t statement;
  schnorr_signature_t signature;
  int status=RLC_ERR;
  bn_null(value); bn_null(order); ec_null(statement); schnorr_signature_null(signature);
  RLC_TRY {
    bn_new(value); bn_new(order); ec_curve_get_ord(order);
    ec_new(statement); schnorr_signature_new(signature);
    for (unsigned i=0;i<n;i++) {
      if (!ledgers[i] || host_ledger_level(ledgers[i])!=0 ||
          (host_ledger_state(ledgers[i])!=HOST_LOCKED &&
           host_ledger_state(ledgers[i])!=HOST_WITHDRAWN)) RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<i;j++) if (ledgers[i]==ledgers[j]) RLC_THROW(ERR_NO_VALID);
      arcs[i]=load_arc(handoffs[i],count,ledgers[i]);
      if (!arcs[i]) RLC_THROW(ERR_NO_VALID);
      if (host_ledger_state(ledgers[i])==HOST_WITHDRAWN) {
        bn_read_bin(signature->e,arcs[i]->records+HOST_CHALLENGE_OFFSET,32);
        bn_read_bin(signature->s,arcs[i]->records+HOST_SCALAR_OFFSET,32);
        ec_read_bin(statement,arcs[i]->records+HOST_STATEMENT_OFFSET,33);
        if (!host_ledger_extract_withdrawal(ledgers[i],signature,statement,value))
          RLC_THROW(ERR_NO_VALID);
      }
    }
    for (unsigned i=0;i<n;i++) {
      if (host_ledger_state(ledgers[i])==HOST_WITHDRAWN) continue;
      if (!read_witness(witnesses[i],count,0,value,order) ||
          !adapt_and_spend(arcs[i],0,value,signature,statement,order,100)) RLC_THROW(ERR_NO_VALID);
    }
    printf("{\"retained_cycle_withdrawal\":true,\"withdrawn_arcs\":%u,"
        "\"observed_withdrawal_hops\":0,\"full_lifecycle\":false}\n",n);
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i=0;i<n;i++) destroy_arc(arcs[i]);
    if (value!=NULL) bn_zero(value);
    bn_free(value); bn_free(order); ec_free(statement);
    if (signature!=NULL) schnorr_signature_free(signature);
  }
  return status;
}

int host_recover_cycle(unsigned count,const int *handoffs,const int *witnesses,
    const int *identifiers,host_ledger **ledgers) {
  if (count<5 || count>255 || !(count&1) || !handoffs || !witnesses || !identifiers || !ledgers)
    return RLC_ERR;
  unsigned n=(count+1)/2;
  recovery_arc *arcs[128]={0};
  bn_t value,identifier,order;
  ec_t source,destination,identity_point;
  schnorr_signature_t source_pre,destination_pre,signature;
  int status=RLC_ERR;
  bn_null(value); bn_null(identifier); bn_null(order);
  ec_null(source); ec_null(destination); ec_null(identity_point);
  schnorr_signature_null(source_pre); schnorr_signature_null(destination_pre);
  schnorr_signature_null(signature);
  RLC_TRY {
    bn_new(value); bn_new(identifier); bn_new(order); ec_curve_get_ord(order);
    ec_new(source); ec_new(destination); ec_new(identity_point);
    schnorr_signature_new(source_pre); schnorr_signature_new(destination_pre);
    schnorr_signature_new(signature);
    for (unsigned i=0;i<n;i++) {
      if (!ledgers[i] || (host_ledger_state(ledgers[i])!=HOST_LOCKED &&
          host_ledger_state(ledgers[i])!=HOST_WITHDRAWN))
        RLC_THROW(ERR_NO_VALID);
      for (unsigned j=0;j<i;j++) if (ledgers[i]==ledgers[j]) RLC_THROW(ERR_NO_VALID);
      arcs[i]=load_arc(handoffs[i],count,ledgers[i]);
      if (!arcs[i]) RLC_THROW(ERR_NO_VALID);
    }
    /* A resumable execution has a withdrawn prefix in recovery order.
     * Validate accepted signatures before allowing any further ledger mutation. */
    int pending=0;
    for (unsigned step=0;step<n;step++) {
      unsigned i=step ? n-step : 0;
      if (host_ledger_state(ledgers[i])==HOST_WITHDRAWN) {
        const unsigned char *record=arcs[i]->records+HOST_RECORD_BYTES*step;
        if (pending || host_ledger_level(ledgers[i])!=step) RLC_THROW(ERR_NO_VALID);
        bn_read_bin(source_pre->e,record+HOST_CHALLENGE_OFFSET,32);
        bn_read_bin(source_pre->s,record+HOST_SCALAR_OFFSET,32);
        ec_read_bin(source,record+HOST_STATEMENT_OFFSET,33);
        if (!host_ledger_extract_withdrawal(ledgers[i],source_pre,source,value)) RLC_THROW(ERR_NO_VALID);
      } else {
        unsigned level=host_ledger_level(ledgers[i]);
        if (level>step || (pending && level!=0)) RLC_THROW(ERR_NO_VALID);
        pending=1;
      }
    }
    if (host_ledger_state(ledgers[0])==HOST_LOCKED &&
        (!read_witness(witnesses[0],count,0,value,order) ||
         !adapt_and_spend(arcs[0],0,value,signature,source,order,100))) RLC_THROW(ERR_NO_VALID);
    for (unsigned step=1;step<n;step++) {
      unsigned outgoing=(n-step+1)%n,incoming=n-step;
      if (host_ledger_state(ledgers[incoming])==HOST_WITHDRAWN) continue;
      const unsigned char *from=arcs[outgoing]->records+HOST_RECORD_BYTES*(step-1);
      const unsigned char *to=arcs[incoming]->records+HOST_RECORD_BYTES*step;
      uint64_t now;
      if (host_read_key(identifiers[outgoing],identifier,identity_point)!=RLC_OK ||
          !relock_to(arcs[incoming],step,witnesses[incoming],value,signature,destination,order) ||
          !host_relock_deadline(&arcs[incoming]->schedule,step,&now)) RLC_THROW(ERR_NO_VALID);
      bn_read_bin(source_pre->e,from+HOST_CHALLENGE_OFFSET,32);
      bn_read_bin(source_pre->s,from+HOST_SCALAR_OFFSET,32);
      bn_read_bin(destination_pre->e,to+HOST_CHALLENGE_OFFSET,32);
      bn_read_bin(destination_pre->s,to+HOST_SCALAR_OFFSET,32);
      ec_read_bin(source,from+HOST_STATEMENT_OFFSET,33);
      ec_read_bin(destination,to+HOST_STATEMENT_OFFSET,33);
      if (!host_recover_into(ledgers[incoming],ledgers[outgoing],source_pre,source,
          destination_pre,destination,identifier,now)) RLC_THROW(ERR_NO_VALID);
    }
    for (unsigned i=0;i<n;i++) if (host_ledger_state(ledgers[i])!=HOST_WITHDRAWN) RLC_THROW(ERR_NO_VALID);
    printf("{\"retained_cycle_recovery\":true,\"withdrawn_arcs\":%u,"
        "\"observed_withdrawal_hops\":%u,\"full_lifecycle\":false}\n",n,n-1);
    status=RLC_OK;
  } RLC_CATCH_ANY { status=RLC_ERR; }
  RLC_FINALLY {
    for (unsigned i=0;i<n;i++) destroy_arc(arcs[i]);
    if (value!=NULL) bn_zero(value);
    if (identifier!=NULL) bn_zero(identifier);
    bn_free(value); bn_free(identifier); bn_free(order);
    ec_free(source); ec_free(destination); ec_free(identity_point);
    if (source_pre!=NULL) schnorr_signature_free(source_pre);
    if (destination_pre!=NULL) schnorr_signature_free(destination_pre);
    if (signature!=NULL) schnorr_signature_free(signature);
  }
  return status;
}
