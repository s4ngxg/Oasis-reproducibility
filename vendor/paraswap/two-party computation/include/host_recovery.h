#ifndef OASIS_HOST_RECOVERY_H
#define OASIS_HOST_RECOVERY_H
#include "host_ledger.h"
/* Consume an observed withdrawal on retained adjacent ledger instances.
 * The host must authenticate adjacency and Preparation inputs. The incoming
 * ledger must already be re-locked to the next address level. No ledger is
 * created here, and no caller-supplied withdrawal witness is accepted. */
int host_recover_into(host_ledger *incoming,const host_ledger *outgoing,
    schnorr_signature_t source_pre,const ec_t source_statement,
    schnorr_signature_t destination_pre,const ec_t destination_statement,
    const bn_t local_identifier,uint64_t now_ns);
/* Local cross-arc correctness gate. Caller selects adjacent admitted arcs.
 * Incoming withdrawal witnesses are not read: recovery must use the observed
 * outgoing withdrawal and the local identifier. Ledgers are controlled fixtures. */
int host_check_recovery(unsigned count,unsigned level,int incoming_fd,int outgoing_fd,
    int identifier_fd,int incoming_witness_fd,int outgoing_witness_fd);
/* Controlled-clock adapter path borrowing two already funded level-zero
 * ledgers. Caller must bind both handoffs to their admitted registries first.
 * The caller retains ownership, including after failure. */
int host_check_recovery_retained(unsigned count,unsigned level,int incoming_fd,int outgoing_fd,
    int identifier_fd,int incoming_witness_fd,int outgoing_witness_fd,
    host_ledger *incoming,host_ledger *outgoing);
/* One retained ledger per arc. Identifier i belongs to arc i's sender.
 * Only arc zero's first withdrawal witness is read. Caller must bind every
 * handoff to its originally admitted registry on every invocation. A failed
 * call can leave accepted spends/re-locks: retry on the same ledger objects.
 * Accepted withdrawals must form a prefix in recovery order; their actual
 * signatures are checked before resuming. This is not durable crash recovery. */
int host_recover_cycle(unsigned count,const int *handoffs,const int *witnesses,
    const int *identifiers,host_ledger **ledgers);
/* All-honest first-level withdrawals on retained, registry-bound ledgers.
 * Already accepted withdrawals are verified and skipped on retry. */
int host_withdraw_cycle(unsigned count,const int *handoffs,const int *witnesses,
    host_ledger **ledgers);
/* Complete Pre-swap is required. Consume delayed re-lock witnesses and a
 * VTD-derived refund signature on the caller's retained ledger. Controlled
 * fixture clock, not a refund mechanism for missing pre-signatures. Caller
 * must bind the handoff to the ledger's admitted registry. Handoff, witness,
 * and receipt descriptors must be sealed. Failure can preserve accepted
 * re-locks; caller retains ownership of the same ledger on every outcome. */
int host_refund_retained(unsigned count,int handoff,int witnesses,int receipt,
    host_ledger *ledger);
#endif
