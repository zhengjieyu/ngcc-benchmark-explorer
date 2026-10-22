#!/usr/bin/env python3
"""Import published NGCC Round 1 measurements; never execute candidate code."""
import argparse
import csv
import datetime as dt
import json
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = 'https://github.com/ngcc-dev/ngcc-harness'
TAXONOMY_SOURCE = 'https://gist.github.com/jedisct1/c7ba25dbae1eb9fe9de23dc339748dd4/73399b48cb2dea6c484b0457e5eb410aa9564ed0'
OPS = {'kem': {'keygen': 'keygen_cycles', 'enc': 'encap_cycles', 'dec': 'decap_cycles'},
       'sign': {'keygen': 'keygen_cycles', 'sign': 'sign_cycles', 'verify': 'verify_cycles'}}


def rows(path):
    with path.open(newline='') as f:
        return list(csv.DictReader((line for line in f if not line.startswith('#')), delimiter=';'))


def number(value):
    if value in (None, ''):
        return None
    try:
        n = int(value)
        return n if n >= 0 else None
    except (ValueError, TypeError):
        return None


def target_for(targets, candidate, instance):
    exact = (candidate, instance)
    if exact in targets:
        return targets[exact], instance, 'exact'
    canonical = re.sub(r'[^a-z0-9]', '', instance.lower())
    matches = [(name, bits) for (cid, name), bits in targets.items()
               if cid == candidate and re.sub(r'[^a-z0-9]', '', name.lower()) == canonical]
    if len(matches) == 1:
        return matches[0][1], matches[0][0], 'normalized-name'
    return '', None, 'unassigned'


def import_dataset(source, commit=None):
    source = Path(source).resolve()
    perf = source / 'performance'
    if not (perf / 'data').is_dir():
        raise ValueError('Missing performance/data in ngcc-harness checkout')
    if commit is None:
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    params = defaultdict(list)
    for r in rows(source / 'data/parameters.csv'):
        params[(r['ID'], r['Instance'], r['Variant'])].append(r)
    targets = {(r['ID'], r['Instance']): r['TargetBits'] for r in rows(perf / 'security_targets.csv')}
    sizes = {(r['ID'], r['Instance']): r for r in rows(perf / 'external_sizes.csv')}
    systems = {r['ID']: r for r in rows(perf / 'systems.csv')}
    with (ROOT / 'data/algorithm_taxonomy.csv').open(newline='') as f:
        taxonomy = {r['candidate_id']: r for r in csv.DictReader(f)}
    with (ROOT / 'data/spec_security_claims.csv').open(newline='') as f:
        spec_claims = {(r['candidate_id'], r['parameter_set']): r for r in csv.DictReader(f)}
    grouped = {}
    diagnostics = defaultdict(int)
    for system, hw in systems.items():
        for path in sorted((perf / 'data' / system / 'records').glob('**/*.json')):
            try:
                d = json.loads(path.read_text())
            except (ValueError, UnicodeDecodeError):
                diagnostics['malformed_json'] += 1
                continue
            kind = str(d.get('candidate', '')).split('-')[0]
            if kind not in OPS or d.get('operation') not in OPS[kind]:
                continue
            candidate, instance = d.get('candidate'), d.get('instance')
            variant = d.get('variant')
            if not all(isinstance(x, str) and x for x in (candidate, instance, variant)):
                diagnostics['missing_identity'] += 1
                continue
            label = d.get('label')
            # Some submissions reuse one Instance for distinct labelled parameter sets.
            # Use the labelled identity when the target/size tables identify it that way.
            parameter_set = label if isinstance(label, str) and (candidate, label) in targets and (candidate, instance) not in targets else instance
            key = (candidate, parameter_set, system, variant, d.get('flags'), d.get('build_flags'))
            matches = params.get((candidate, instance, {'reference': 'Reference_Implementation'}.get(variant, variant)), [])
            if not matches:
                # Source metadata is still retained; never join to a different instance.
                matches = [v for (cid, inst, _), values in params.items() if cid == candidate and inst == instance for v in values]
            p = next((v for v in matches if v['SourceDirectory'].rstrip('/').lower().endswith('/' + str(label).lower())), None) or (matches[0] if len(matches) == 1 else None)
            if p is None:
                diagnostics['unmatched_parameter_set'] += 1
                continue
            if key not in grouped:
                ext = sizes.get((candidate, parameter_set), {})
                classification = taxonomy.get(candidate, {})
                target_bits, target_instance, target_match = target_for(targets, candidate, parameter_set)
                spec_claim = spec_claims.get((candidate, parameter_set), {}) if not target_bits else {}
                spec_bits = number(spec_claim.get('classical_target_bits'))
                grouped_bits = number(target_bits) or (spec_bits if spec_bits in (128, 256, 512) else None)
                source_directory = None
                if variant == 'reference':
                    proposed = f"{candidate}/{p['SourceDirectory']}"
                    if (source / proposed).is_dir():
                        source_directory = proposed
                elif variant == 'optimized-avx2' and candidate == 'sign-02':
                    proposed = f'{candidate}/Implementations/Optimized_Implementation/{instance}-avx2'
                    if (source / proposed).is_dir():
                        source_directory = proposed
                base = {
                    'id': '|'.join(str(x) for x in key), 'candidate_id': candidate,
                    'algorithm': p['Algorithm'], 'type': 'KEM' if kind == 'kem' else 'Signature',
                    'parameter_set': parameter_set, 'implementation': variant, 'platform': system,
                    'source_directory': source_directory,
                    'candidate_directory': candidate,
                    'category': classification.get('category') or None,
                    'assumption': classification.get('assumption') or None,
                    'classification_source': TAXONOMY_SOURCE if classification else None,
                    'hardware': hw['Description'], 'architecture': hw['Arch'],
                    'security_group': f'NGCC-{grouped_bits}' if grouped_bits else None,
                    'security_group_origin': 'target-table' if target_bits else ('specification' if grouped_bits else None),
                    'security_target_instance': target_instance,
                    'security_target_match': target_match,
                    'security_note': 'NGCC comparison target, not independently validated security',
                    'spec_classical_target_bits': spec_bits,
                    'spec_claim_source': spec_claim.get('source_file') or None,
                    'spec_claim_note': spec_claim.get('evidence_note') or None,
                    'build_profile': d.get('flags'), 'build_flags': d.get('build_flags'),
                    'public_key_bytes': number(ext.get('PublicKeyBytes')),
                    'secret_key_bytes': number(p.get('SecretKeyBytes')),
                    'ciphertext_bytes': number(ext.get('CiphertextBytes')),
                    'shared_secret_bytes': number(p.get('SharedSecretBytes')),
                    'signature_bytes': number(ext.get('SignatureBytes')),
                    'size_basis': ext.get('Basis'), 'measurements': {}, 'missing': [],
                    'source_commit': commit,
                    'metadata_sources': ['data/parameters.csv', 'performance/security_targets.csv', 'performance/external_sizes.csv'],
                }
                grouped[key] = base
            rec = grouped[key]
            metric = OPS[kind][d['operation']]
            relative = path.relative_to(source).as_posix()
            value = d.get('mean_cycles')
            valid = d.get('status') == 'complete' and isinstance(value, (int, float)) and value >= 0
            if valid and rec['measurements'].get(metric) is None:
                seconds = d.get('mean_seconds')
                rec['measurements'][metric] = {'cycles': value, 'source_file': relative,
                    'kat': d.get('kat'), 'kat_not_passed': bool(d.get('kat_not_passed')),
                    'build_flags': d.get('build_flags'),
                    'seconds': seconds if isinstance(seconds, (int, float)) and seconds >= 0 else None}
            else:
                rec['missing'].append({'metric': metric, 'source_file': relative,
                    'reason': d.get('status') if not valid else 'duplicate'})
                diagnostics['failed_or_duplicate'] += 1
    records = sorted(grouped.values(), key=lambda r: (r['type'], r['algorithm'], r['parameter_set'], r['platform'], r['implementation']))
    for rec in records:
        for metric in OPS['kem' if rec['type'] == 'KEM' else 'sign'].values():
            if metric not in rec['measurements']:
                rec['missing'].append({'metric': metric, 'reason': 'not published for this configuration'})
    return {'schema_version': 1, 'upstream': UPSTREAM, 'source_commit': commit,
        'synced_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'methodology': 'Independent ngcc-harness Round 1 campaign; not NICCS results',
        'records': records, 'diagnostics': dict(diagnostics)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, default=Path(os.environ.get('NGCC_HARNESS_PATH', ROOT.parent / 'ngcc-harness')))
    ap.add_argument('--commit', help='Explicit pinned commit; must match checkout HEAD')
    ap.add_argument('--output', type=Path, default=ROOT / 'data/normalized.json')
    args = ap.parse_args()
    actual = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True).strip()
    if args.commit and args.commit != actual:
        ap.error(f'Checkout HEAD {actual} differs from requested {args.commit}')
    dataset = import_dataset(args.source, actual)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + '\n')
    print(f"Imported {len(dataset['records'])} records from {actual}: "
          f"{sum(r['type']=='KEM' for r in dataset['records'])} KEM, "
          f"{sum(r['type']=='Signature' for r in dataset['records'])} signature")


if __name__ == '__main__':
    main()
