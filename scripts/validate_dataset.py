#!/usr/bin/env python3
"""Fail publication if an upstream import is empty or mismatched."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--data', type=Path, default=Path(__file__).resolve().parents[1] / 'data/normalized.json')
parser.add_argument('--commit', required=True)
args = parser.parse_args()
data = json.loads(args.data.read_text())
records = data.get('records')
if data.get('schema_version') != 1 or data.get('source_commit') != args.commit:
    parser.error('dataset schema or source commit does not match the harness checkout')
if not isinstance(records, list) or not records:
    parser.error('imported dataset has no records')
if any(r.get('source_commit') != args.commit for r in records):
    parser.error('a record has a different source commit')
print(f'Validated {len(records)} records from {args.commit}')
