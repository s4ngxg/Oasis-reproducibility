# Reduced-cost WAN reproduction

This recipe checks the same five native C/RELIC configurations, mutually
authenticated ZeroMQ CURVE transport, synchronized schedule, and strict analyzer
used by the publication campaign. It deliberately uses only `n=3,8`, `p=1`, five
measured paired trials, and one warm-up. It is a functional reproduction, not a
replacement for the publication-scale statistical matrix.

Use fixed-performance EC2 instances in `us-east-1`, `eu-central-1`, and
`ap-southeast-1`. Open the selected service port on the US responder only to the
active client's public `/32`. Run EU and Singapore sequentially.

On the US responder, start the matching role first:

```bash
BASE_PORT=9000 bash scripts/run_reduced_wan_role.sh \
  server eu_to_us oasis-eu-reduced "$HOME/oasis-curve-eu/responder"
```

On the EU client:

```bash
BASE_PORT=9000 bash scripts/run_reduced_wan_role.sh \
  client eu_to_us oasis-eu-reduced \
  "$HOME/oasis-curve-eu/initiator" US_PUBLIC_IP
```

Validate the synchronized role outputs:

```bash
python3 scripts/analyze_cloud_results.py \
  results/cloud/reduced/oasis-eu-reduced-client.json \
  results/cloud/reduced/oasis-eu-reduced-server.json \
  --json-out results/cloud/reduced/oasis-eu-reduced-analysis.json \
  --md-out results/cloud/reduced/oasis-eu-reduced-analysis.md
```

Repeat with route `sg_to_us`, a new campaign ID, and the Singapore credentials.
The raw schema records EC2 placement and rejects a role launched in the wrong
region. The analyzer also rejects schedule, source, binary, authentication,
connection-lifecycle, or paired-trial mismatches.
