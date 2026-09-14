# Native authenticated cloud deployment

This procedure runs the primary same-backend ParaSwap Pre-swap campaign. The
US VM is the responder; Frankfurt or Singapore is the initiator. Run one route
at a time. The native transport is ZeroMQ CURVE over TCP, not TLS.

## 1. Package and bootstrap

On the development machine:

```bash
make package
```

Upload the source archive and its SHA-256 file to the US VM and the active
client VM. Verify the checksum, extract, and run on each VM:

```bash
cd ~/oasis-reproducibility-artifact
make bootstrap
make test
mkdir -p results
ulimit -n 65535
```

The bootstrap installs the pinned C/RELIC build dependencies plus SciPy,
`strace`, `tcpdump`, and `tshark`. Record a fresh VM image after bootstrap if
the final campaign must use identical software across placements.

The final-evidence launcher fixes every workload and uses the same service port
`9000` for all profiles. Profiles and routes must run sequentially:

```bash
DRY_RUN=1 scripts/run_final_evidence_role.sh \
  server eu_to_us primary preswap-eu-primary-v4 AUTH_DIR
```

Valid profiles are `primary`, `load`, `allocation`, `syscall`, and `pcap`.
Run the same profile and campaign identifier at both endpoints. The server form
takes five arguments; the client form takes the US responder address as a sixth
argument. The resulting role JSON is written under `results/cloud/final/`.
The explicit commands in the following sections document the same schedule;
the launcher is the preferred way to execute it without parameter drift.

## 2. Generate and distribute CURVE credentials

Use a distinct credential pair for each route. The preferred deployment creates
the initiator secret on its client VM and the responder secret on the US VM,
then exchanges only `*_public.key` files. `make auth-keys` can create the
role-separated staging directories on each endpoint:

```bash
cd ~/oasis-reproducibility-artifact
make auth-keys AUTH_DIR="$HOME/oasis-curve-final"
```

Install only the matching peer public key into each route directory. The
responder retains its route-specific secret key and the allowed initiator public
key; the initiator retains its secret key and the pinned responder public key.
Secret files must retain mode `0600`. The source packager excludes `auth/`, the
generated CURVE/TLS credentials, and every `*.pem` and `*.crt`; never add
deployment credentials to Git or result bundles. The only `.key` files retained
are the three hash-pinned ParaSwap benchmark fixtures required by the upstream
artifact, not live route credentials.

## 3. Determine the service port and configure the Security Group

Use the largest planned load before changing firewall rules:

```bash
python3 scripts/run_cloud_campaign.py \
  --role server --route eu_to_us --campaign-id preswap-eu-load-final \
  --participants 8,16 --concurrent-pairs 1,64,128,1024 \
  --trials 20 --warmup 5 --base-port 9000 \
  --output /tmp/unused.json --dry-run
```

With this matrix, the reported `service_port` is `9000` and the minimum soft
file-descriptor limit is 2304. Allow TCP port `9000` inbound on the US VM only
from the active client VM public IPv4 `/32`; do not use `0.0.0.0/0`. No inbound
campaign port is required on the client. CURVE is the authentication mechanism;
the Security Group is an additional network boundary.

The responder exposes one CURVE ROUTER on this port. Every participant-pair
session creates a separate client connection to the same endpoint. The gateway
binds each authenticated connection to its `pair_id` and `execution_id`, then
forwards it to a process-isolated RELIC worker over a local IPC socket. Worker
IPC endpoints are never opened in the Security Group. The gateway owns a
bounded FIFO admission queue and dispatches each admitted session to one of a
fixed number `W` of long-lived workers. A worker remains session-affine until a
terminal `DONE`, `ABORT`, or failed `FINAL_STATUS`, then returns to the pool.

## 4. Primary paired timing campaign

Start the US responder first:

```bash
cd ~/oasis-reproducibility-artifact
nohup python3 scripts/run_cloud_campaign.py \
  --role server --bind 0.0.0.0 \
  --route eu_to_us --campaign-id preswap-eu-primary-final \
  --participants 3,5,8,16 --concurrent-pairs 1 \
  --trials 100 --warmup 10 --base-port 9000 \
  --auth-dir "$HOME/oasis-curve-final/responder" \
  --output results/preswap-eu-primary-final-server.json \
  > results/preswap-eu-primary-final-server.log 2>&1 &
echo $! > results/preswap-eu-primary-final-server.pid
```

Then start the Frankfurt initiator with identical workload arguments:

```bash
cd ~/oasis-reproducibility-artifact
nohup python3 scripts/run_cloud_campaign.py \
  --role client --host US_SERVER_PUBLIC_IP \
  --route eu_to_us --campaign-id preswap-eu-primary-final \
  --participants 3,5,8,16 --concurrent-pairs 1 \
  --trials 100 --warmup 10 --base-port 9000 \
  --auth-dir "$HOME/oasis-curve-final/initiator" \
  --output results/preswap-eu-primary-final-client.json \
  > results/preswap-eu-primary-final-client.log 2>&1 &
echo $! > results/preswap-eu-primary-final-client.pid
```

Completion requires both `wrote=...json` in the logs and both launcher PIDs to
have exited. Any failed stage invalidates the paired schedule.

## 5. Load campaign

After primary analysis succeeds, rerun both roles with a new campaign ID and:

```text
--participants 8,16
--concurrent-pairs 1,64,128,1024
--trials 20 --warmup 5
--io-timeout-ms 900000 --process-timeout-seconds 930
```

Keep the default five configurations. Parameter `n` determines the ParaSwap
cycle and `k=2n-1` items per pair; `p` is the independent number of concurrent
pair sessions. A `p=1024` run is a contention stress test of the current
event-driven gateway and fixed worker pool, not a 1,024-participant swap.
Every result records configured workers, peak busy workers, queue depth, queue
wait, assignments, and rejected sessions. A valid timing campaign requires
exactly `p` assignments and zero rejection.

## 6. Separate systems profiles

Do not enable these profilers in primary timing runs.

Allocation profile, on both roles with matching arguments:

```text
--profiling-mode allocation
--participants 8,16 --concurrent-pairs 1,128
--trials 10 --warmup 2
```

This reports allocation calls and requested bytes in the instrumented artifact
sources. It does not claim to intercept every allocation inside dynamically
linked RELIC, PARI, ZeroMQ, or libc.

Syscall profile, on both roles:

```text
--profiling-mode syscall
--profile-output-dir results/syscall-ROLE
--participants 8 --concurrent-pairs 1,128
--trials 5 --warmup 1
```

Analyze each paired allocation or syscall campaign with:

```bash
python3 scripts/analyze_system_profiles.py CLIENT.json SERVER.json \
  --json-out results/system-profile.json \
  --md-out results/system-profile.md
```

For exact TCP evidence, wrap a reduced all-configuration timing campaign on
each endpoint. Both capture bounds must equal that campaign's service port:

```bash
bash scripts/capture_native_campaign.sh ens5 9000 results/ROLE.pcap -- \
  python3 scripts/run_cloud_campaign.py ...

python3 scripts/analyze_native_pcap.py results/ROLE.pcap \
  --role ROLE --local-ip PRIVATE_IPV4 \
  --campaign-id oasis-eu-pcap-v4 --route eu_to_us \
  --service-port 9000 \
  --json-out results/ROLE-pcap.json --md-out results/ROLE-pcap.md
```

The PCAP analyzer reports campaign-scoped TCP segments, payload bytes,
retransmissions, payload direction changes, and a TCP ACK-derived RTT
distribution (min/P50/P95/P99/max). TLS record and TLS session-reuse states are
explicitly not applicable to ZeroMQ CURVE. Host `/proc` counter deltas in timing JSON are
diagnostic and can include unrelated traffic; do not substitute them for PCAP.

## 7. Validate and analyze timing evidence

Place both role JSON files in one repository copy:

```bash
python3 scripts/analyze_cloud_results.py CLIENT.json SERVER.json \
  --json-out results/timing-analysis.json \
  --md-out results/timing-analysis.md
```

The analyzer rejects incomplete or duplicate schedules, source/runtime/auth
mismatches, wrong `k` or `p`, execution-ID/frame/byte mismatches, unexpected MSM
calls, verifier fallback, and profiler-contaminated timing evidence. It reports
pair and stage p50/p95/p99, throughput, application goodput, endpoint CPU, RSS,
context switches, kernel scheduler wait, sampled run queue, fairness, and
host-level interface counters.

After every role pair passes its analyzer, generate reader-facing assets
without manually transcribing table cells:

```bash
python3 scripts/build_final_experiment_report.py \
  --require-final-matrix \
  --timing eu_primary=results/eu-primary-analysis.json \
  --timing eu_load=results/eu-load-analysis.json \
  --timing sg_primary=results/sg-primary-analysis.json \
  --timing sg_load=results/sg-load-analysis.json \
  --system eu_allocation=results/eu-allocation-analysis.json \
  --system eu_syscall=results/eu-syscall-analysis.json \
  --pcap eu_client=results/eu-client-pcap.json \
  --pcap eu_server=results/eu-server-pcap.json \
  --pcap sg_client=results/sg-client-pcap.json \
  --pcap sg_server=results/sg-server-pcap.json \
  --cost cloud=results/cloud-cost-report.json \
  --out-dir results/final-paper-assets
```

The output includes CSV tables, figures, a generated `paper_results.tex`,
SHA-256 checksums, and `CLAIM_TO_EVIDENCE.json`. The builder rejects historical
schemas, mixed or missing primary/load campaigns, incomplete per-campaign
factorial effects, and verifier fallbacks. Include the generated LaTeX fragment
instead of manually transcribing numeric table cells.

For Singapore, change `eu_to_us` to `sg_to_us`, use a distinct campaign ID,
replace the US Security Group source with the Singapore public `/32`, and start
only after the EU route has stopped. Keep source hashes, build settings,
workload, and runtime settings identical. Public-key fingerprints must remain
identical across all profiles of one route; different client placements use
distinct route-scoped identities.

## Evidence boundary

This campaign measures native Pre-swap. The local lifecycle harness covers the
five ParaSwap phases with deterministic ledger and timed-release adapters, but
does not submit funded public-chain transactions. The native server is one
measured event-driven public gateway plus a fixed pool of long-lived,
process-isolated cryptographic workers. This campaign can support claims about
that implementation after schema validation. Claims about a second VM family,
multiple days/placements, multi-cloud routing, or public-testnet end-to-end
impact still require separate evidence and must not be inferred from this run.
