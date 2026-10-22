# Data and methods

Detailed provenance, import rules, comparison scope, and known limits for the imported dataset.

## Reproduce the initial data snapshot

```bash
git clone https://github.com/ngcc-dev/ngcc-harness.git /path/to/ngcc-harness
git -C /path/to/ngcc-harness checkout 8f6bd88576b8725b1cf1a19c360290cdddc0e830
python3 scripts/sync_ngcc.py --source /path/to/ngcc-harness --commit 8f6bd88576b8725b1cf1a19c360290cdddc0e830
```

The importer reads `data/parameters.csv`, `performance/security_targets.csv`, `performance/external_sizes.csv`, `performance/systems.csv` and `performance/data/<system>/records/**/*.json`. No candidate code is built or run. Each normalized measurement stores its exact JSON path and source commit. The generated `data/normalized.json` stores the synchronization timestamp and diagnostics. The script rejects a supplied commit that differs from checkout HEAD. `python3 scripts/sync_ngcc.py --source ...` also imports the current checkout when intentionally updating.

The initial pinned snapshot contained **350 KEM and 399 signature records** over two published systems. A record is one parameter set, machine, implementation and build configuration. Some lack individual operation results or external size values; these remain null or explicitly listed as missing. The importer does not copy upstream implementation code. Original submission code may carry candidate-specific licenses; check those before redistribution.

Category and assumption/hard-problem labels come from the separately pinned [NGCC Round 1 candidate survey](https://gist.github.com/jedisct1/c7ba25dbae1eb9fe9de23dc339748dd4/73399b48cb2dea6c484b0457e5eb410aa9564ed0), transcribed into `data/algorithm_taxonomy.csv` and joined by the stable `sign-NN` / `kem-NN` candidate ID. The crosswalk covers all 75 KEM and signature candidates in this snapshot and was checked against the official-name ordering in the harness. These labels summarize the scheme design; they do not establish the truth of its security assumptions or a candidate's current status. The detail panel links to the classification source.

The detail panel's **Implementation resources** links point to the exact implementation source directory within the pinned ngcc-harness commit. Reference paths come from `data/parameters.csv` and are checked against the checkout. The three published BiT AVX2 records use their verified optimized directories. Candidate-directory links are also provided. All 749 records in the initial snapshot have an exact implementation directory link; future records with no verified path will show that limitation instead of linking a potentially different variant.

The upstream repository does not have a repository-wide license file at the inspected commit. The redistribution terms for its benchmark data were not explicit in the inspected documentation. You can set `NGCC_HARNESS_PATH` to use the short `python3 scripts/sync_ngcc.py` command; by default it looks for a sibling `ngcc-harness` checkout.

## Interpretation

Both chart axes are minimized. A point dominates another when it is no worse on both axes and strictly better on at least one. Ties remain non-dominated. Pareto calculations are partitioned by claimed security target, exact platform/hardware, implementation variant, build profile and compiler flags. A flag repeated verbatim is counted once, unless a conflicting value of the same option (for example another `-std=` or `-O` level) appears between the two copies; the upstream build sometimes appends `-std=c99` to flags that already start with it, and without this rule those records formed a separate group. Layer 1 contains points not dominated in their comparison group; remove it and repeat to obtain Layer 2, Layer 3, and so on. A layer is a partial order, not an overall ranking. The ordinary explorer shows complete measured pairs without a Pareto label. The optional trade-off view excludes points missing either selected value, lacking a comparison target or marked as KAT failures, and lists actual dominating peers in the detail panel. When multiple configuration groups are visible, each has its own frontier; these are **not** a combined ranking. Logarithmic axes are enabled by default for the wide range of published values.

The ICCS public-key submission requirements specify mandatory 128/256/512-bit classical strengths and an optional 384-bit strength. ICCS explicitly declined a proposed 192-bit NGCC level; 192-bit parameter sets on this site are extra submission variants. The UI displays plain bit strengths; internal comparison groups and the source of each value remain recorded. Public-key, ciphertext and signature sizes use `external_sizes.csv` because the upstream campaign distinguishes external encodings from benchmark allocation sizes. Secret-key and shared-secret sizes come from `data/parameters.csv`. Cycles use `mean_cycles` in each operation's published record. The website makes no live benchmark requests. Scheduled jobs check the upstream repository daily and rebuild the static snapshot when its HEAD changes; each displayed result remains pinned to the published source commit.

## Source investigation and limits

The harness organizes Round 1 submissions in `kem-*`, `sign-*`, `kex-*` and `hash-*` directories. `data/parameters.csv` maps implementation instances and parameter names; performance records are JSON by machine, candidate, instance and operation. The performance README documents x86_1 (Intel Core i7-12700) and arm_1 (Snapdragon X Elite) and the reference/optimized campaign policy. Current optimized coverage is limited, so reference is the default UI selection. Failed, malformed and incomplete records are reported or skipped, never imputed. The importer does not resolve variable-length signature distributions beyond the upstream size basis.

Upstream source links in the detail panel point to the pinned ngcc-harness commit.

The displayed strength comes from `performance/security_targets.csv` when present and otherwise from a documented specification claim. An empty `TargetBits` value does not imply an invalid or insecure scheme. The importer also matches unique punctuation-only name variants (for example `CS_128` to `CS-128`) and records that match in each row.

## Specification target classification

`data/spec_security_claims.csv` records classical security targets stated in the pinned candidate specifications for parameter sets without an NGCC comparison target. For 128/256/512-bit claims, the importer uses the same comparison bucket as target-table entries while retaining `security_group_origin` and the linked specification in the detail panel. All user-facing strength labels use plain `N-bit` wording. This is a site grouping of stated classical strengths, not independent validation. The 192/384-bit sets retain their own displayed bit strength; they are not included in the optional two-metric comparison. The ICCS requirements make 384 bits optional and do not include 192 bits. `POLARLAC-Light` has no discrete target claim; its specification reports 121.6-bit classical Core-SVP and 143.8-bit refined BKZ estimates. The pinned specifications and the evidence notes in the CSV support each mapping. YuanYang and Sigurd use distinct benchmark labels even where their parameter metadata reuse an instance name; the importer resolves labels against the target and size tables.

Scatter plots use color for claimed classical strength (128/192/256/384/512-bit or not stated) and shape for problem family (lattice, code, isogeny, hash, symmetric/MPCitH, multivariate, other). Legends list only values present in the current filtered plot. In the trade-off view, a white outline marks a point with no qualifying alternative. Range inputs initially display the full-data observed minimum and maximum for the selected primitive; those defaults do not filter records until edited.
