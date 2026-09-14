# Closest external comparator

## Verified bibliographic record

Crossref DOI lookup on 2026-09-10 confirmed:

- Menghao Wang, Haotian Deng, Mengxuan Liu, Meng Li, Chuan Zhang,
  Licheng Wang, and Liehuang Zhu.
- Scriptless Atomic Swap With Batch Processing.
- IEEE Transactions on Information Forensics and Security, volume 21,
  pages 6300-6315, 2026.
- DOI: https://doi.org/10.1109/TIFS.2026.3707794
- Publisher record: https://ieeexplore.ieee.org/document/11580368/
- Metadata source: https://api.crossref.org/works/10.1109/TIFS.2026.3707794

The metadata references the original ParaSwap paper. This establishes citation
presence, not the technical relationship or relative performance.

## Access and evidence boundary

The OpenAlex record W7166064094 reports no open full text and no abstract.
The IEEE landing page returned no readable content in this access attempt.
No matching local PDF was found. This does not establish that an author copy
or implementation is unavailable elsewhere.

Additional public lookups on 2026-09-10:

- Semantic Scholar Graph API, DOI lookup with `title,url,openAccessPdf,externalIds`:
  paper ID `fa561d7ee89f8cf8eb1f8ade9184201480a517f5`, DBLP key
  `journals/tifs/WangDLLZWZ26`, `openAccessPdf.status=CLOSED`, empty PDF URL.
- arXiv API exact-title query
  `ti:"Scriptless Atomic Swap With Batch Processing"`: zero results.

These queries did not yield full text. They are not an exhaustive author-site
or institutional-repository search. An authorized author/publisher PDF is still
needed before making algorithm-level claims from this comparison.

Review0209 describes batching of transaction-lock/time-lock primitives. That
description is a reviewer statement, not independently verified here against
the full paper. Do not turn it into a definitive novelty or performance claim.

## Comparison still required

| Question | Current OASIS evidence | Comparator evidence needed |
|---|---|---|
| Unit batched | Repeated per-arc two-party pre-signing items, k=2n-1 | Exact algorithms and transaction graph |
| Optimization | Shared transcript/session and salted multi-key aggregate verification with MSM | Primitive, message, transaction and verification savings |
| Security | Conditional construction mapping; no full concrete reduction | Exact theorem and assumptions, adversary and abort model |
| Integration | Native signing plus retained local ledger adapter | Implemented chain/host interfaces and available artifact |
| Evaluation | Component WAN tooling and local lifecycle branch evidence | Workloads, crypto parameters, network controls, raw measurements |

Before implementing a benchmark comparator, inspect the full algorithms and
map equivalent work and security parameters. Do not equate a phase-coalesced
internal baseline with this external construction or compare unrelated latency
figures as a speedup. A technical comparison may be possible even if no runnable
artifact is available; empirical comparison remains unestablished.

## Citation ready for manuscript revision

```bibtex
@article{wang2026scriptlessbatch,
  author = {Wang, Menghao and Deng, Haotian and Liu, Mengxuan and Li, Meng
            and Zhang, Chuan and Wang, Licheng and Zhu, Liehuang},
  title = {Scriptless Atomic Swap With Batch Processing},
  journal = {IEEE Transactions on Information Forensics and Security},
  volume = {21},
  pages = {6300--6315},
  year = {2026},
  doi = {10.1109/TIFS.2026.3707794}
}
```

The manuscript has not been edited by this verification step.
