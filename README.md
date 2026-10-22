# NGCC Benchmark Explorer

[Explore the website](https://zhengjieyu.github.io/ngcc-explorer/)

Interactive comparison of KEM and signature schemes from the NGCC Round 1 submissions. Filter schemes and implementations, inspect key and signature sizes and performance, and explore two-metric trade-offs.

The repository includes a reproducible snapshot of [ngcc-harness](https://github.com/ngcc-dev/ngcc-harness)'s independent measurements: **749 records** across its x86 and Arm systems. These are not measurements run by this project or results from NICCS. Scheduled GitHub Actions check the upstream revision daily; when it changes, the data are re-imported, validated, and the hosted site is rebuilt. The displayed revision identifies the exact upstream commit, and the import date changes only after a new revision is published. See [Data and methods](docs/DATA_AND_METHODS.md) for the pinned commit, import steps, provenance, and interpretation limits.

## Development

```bash
npm ci
npm run dev       # http://127.0.0.1:5173/
npm run build     # static site in build/
npm run preview   # preview the build locally
```

## Testing

```bash
npm test
npm run check
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Contributing

Suggestions and corrections are welcome. Open an [issue](https://github.com/zhengjieyu/ngcc-benchmark-explorer/issues) or submit a [pull request](https://github.com/zhengjieyu/ngcc-benchmark-explorer/pulls).

## Stack

SvelteKit · Svelte 5 · TypeScript · Tailwind CSS v4 · Vega-Lite

The layout was inspired by the [NIST Signatures Zoo](https://github.com/PQShield/nist-sigs-zoo).
