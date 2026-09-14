# Cloud cost accounting

Cloud cost evidence is generated from explicit resource quantities and a dated
pricing source. The artifact does not hard-code prices because regional prices can
change. Copy `config/cloud_cost_input.template.json`, set `template` to `false`,
and fill every quantity and unit price from the final campaign billing period.

Each publication campaign must report measured, warm-up, and failed runs. Line
items must separately cover:

- compute instance-hours in `us-east-1`, `eu-central-1`, and `ap-southeast-1`;
- storage capacity and retention duration;
- inter-region and Internet data transfer charged by the provider.

Record the authoritative HTTPS pricing page and retrieval timestamp, then run:

```bash
python3 scripts/build_cloud_cost_report.py \
  config/cloud_cost_input.final.json \
  --json-out results/cloud/cloud-cost-report.json \
  --md-out results/cloud/cloud-cost-report.md
```

The final evidence builder accepts exactly one cost report and rejects it unless it
covers every timing campaign and all three cost categories and compute regions. The
retrieval timestamp must be a valid ISO-8601 UTC value ending in `Z`. Every timing
campaign must also have a matching campaign row with the same route, positive
measured and warm-up stage counts matching the analyzed matrix, non-negative
failed-run count, and positive compute cost. One run in this report means one
configuration stage, not one participant-pair connection: the primary matrix has
2,000 measured and 200 warm-up stages per route, while the load matrix has 800
measured and 200 warm-up stages per route. Compute line items must contain positive
instance-hours for `us-east-1`,
`eu-central-1`, and `ap-southeast-1`; explicit zero storage or transfer quantities
remain valid when the provider did not charge those categories.
