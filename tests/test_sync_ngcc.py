import json
import tempfile
import unittest
from pathlib import Path
from scripts.sync_ngcc import import_dataset, number, target_for


class ImportTests(unittest.TestCase):
    def test_target_name_normalization_respects_blank_and_ambiguity(self):
        targets = {('sign-07', 'CS-128'): '128', ('sign-08', 'Rhyme-SHAKE-384'): '', ('sign-09', 'A-1'): '128', ('sign-09', 'A_1'): '256'}
        self.assertEqual(target_for(targets, 'sign-07', 'CS_128'), ('128', 'CS-128', 'normalized-name'))
        self.assertEqual(target_for(targets, 'sign-08', 'Rhyme-SHAKE-384'), ('', 'Rhyme-SHAKE-384', 'exact'))
        self.assertEqual(target_for(targets, 'sign-09', 'A 1'), ('', None, 'unassigned'))

    def test_number_rejects_missing_and_malformed(self):
        self.assertIsNone(number(''))
        self.assertIsNone(number('failed'))
        self.assertEqual(number('120'), 120)

    def test_matching_and_failed_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'data').mkdir()
            perf = root/'performance'
            (perf/'data/x86_1/records/kem-01').mkdir(parents=True)
            (root/'kem-01/ref/A-128').mkdir(parents=True)
            (root/'data/parameters.csv').write_text('ID;Type;Algorithm;Instance;Variant;SourceDirectory;SecretKeyBytes;SharedSecretBytes\nkem-01;kem;A;A-128;Reference_Implementation;ref/A-128;30;32\n')
            (perf/'security_targets.csv').write_text('ID;Instance;TargetBits\nkem-01;A-128;128\n')
            (perf/'external_sizes.csv').write_text('ID;Instance;PublicKeyBytes;CiphertextBytes;SignatureBytes;Basis\nkem-01;A-128;20;40;;encoded\n')
            (perf/'systems.csv').write_text('ID;Arch;Hostname;Description\nx86_1;x86_64;h;CPU\n')
            base={'candidate':'kem-01','instance':'A-128','variant':'reference','flags':'guide','build_flags':'-O2','kat':'PASS'}
            for op,status,cycles in [('keygen','complete',100),('enc','failed',None),('dec','complete',200)]:
                (perf/f'data/x86_1/records/kem-01/A-128__{op}.json').write_text(json.dumps({**base,'operation':op,'status':status,'mean_cycles':cycles,'mean_seconds':0.001 if cycles else None}))
            (perf/'data/x86_1/records/kem-01/bad.json').write_text('{')
            result=import_dataset(root,'testcommit')
            self.assertEqual(len(result['records']),1)
            row=result['records'][0]
            self.assertEqual(row['parameter_set'],'A-128')
            self.assertEqual(row['security_group'],'NGCC-128')
            self.assertEqual(row['public_key_bytes'],20)
            self.assertEqual(row['source_directory'],'kem-01/ref/A-128')
            self.assertEqual(row['category'], 'lattice')
            self.assertEqual(row['measurements']['decap_cycles']['cycles'],200)
            self.assertEqual(row['measurements']['decap_cycles']['seconds'],0.001)
            self.assertNotIn('encap_cycles',row['measurements'])
            self.assertTrue(any(m['metric']=='encap_cycles' for m in row['missing']))
            self.assertEqual(result['diagnostics']['malformed_json'],1)

    def test_taxonomy_coverage_of_pinned_dataset(self):
        dataset = json.loads((Path(__file__).parents[1]/'data/normalized.json').read_text())
        self.assertEqual(len(dataset['records']), 749)
        self.assertTrue(all(r['category'] and r['assumption'] and r['classification_source'] for r in dataset['records']))
        self.assertTrue(all(r['source_directory'] for r in dataset['records']))
        ungrouped = [r for r in dataset['records'] if r['security_group'] is None]
        self.assertEqual(len(ungrouped), 118)
        self.assertTrue(all(r['spec_claim_source'] for r in ungrouped))
        self.assertEqual({r['spec_classical_target_bits'] for r in ungrouped if r['parameter_set'] == 'POLARLAC-Light'}, {None})
        self.assertEqual({r['spec_classical_target_bits'] for r in ungrouped if r['parameter_set'] == 'Rhyme-SHAKE-384'}, {384})
        spec_grouped = [r for r in dataset['records'] if r['security_group_origin'] == 'specification']
        self.assertEqual(len(spec_grouped), 38)
        self.assertTrue(all(r['security_group'] == f"NGCC-{r['spec_classical_target_bits']}" for r in spec_grouped))
        self.assertTrue(all(r['spec_claim_source'] for r in spec_grouped))
        yuanyang = [r for r in dataset['records'] if r['candidate_id'] == 'kem-40']
        self.assertEqual({r['security_group'] for r in yuanyang}, {'NGCC-128', 'NGCC-256', 'NGCC-512'})
        self.assertEqual(len(yuanyang), 6)

if __name__=='__main__': unittest.main()
