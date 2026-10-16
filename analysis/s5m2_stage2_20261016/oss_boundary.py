"""Hash-pin previously audited OSS and re-read selected actual source spans.
Reuses, labels and hashes the prior full scan instead of repeating its scan.
No source build, target execution, broad keyword scan or model substitution.
"""
import collections
import tarfile
from pathlib import Path, PurePosixPath
from common import ROOT, WORK, RESULTS, file_id, digest, load, save, config

def main():
    oldpath = WORK / 'references/boot/results_checked/source_audit.json'
    old = load(oldpath)
    reports = {}
    for filename, prior in old['archives'].items():
        p = Path(config()['oss_root']) / filename
        actual = file_id(p)
        assert actual == {'size': prior['bytes'], 'sha256': prior['sha256']}, filename
        # Read the previously selected source files with real function bodies,
        # plus exact board config/DTS; not every prior broad anchor file.
        targets = {r['path']: r for r in prior['selected_sources']
                   if r['functions'] or r['path'].endswith('_defconfig')
                   or r['path'].endswith('.dts') or r['path'].endswith('-rtos.h')}
        found = {}
        selected = []
        with tarfile.open(p, 'r|gz') as tar:
            for m in tar:
                name = PurePosixPath(m.name).as_posix()
                if name not in targets:
                    continue
                assert m.isfile() and name not in found
                data = tar.extractfile(m).read()
                original = targets[name]
                assert len(data) == original['bytes'] and digest(data) == original['sha256'], name
                functions = []
                for f in original['functions']:
                    span = data[f['byte_start']:f['byte_end_exclusive']]
                    assert digest(span) == f['span_sha256'], (name, f['name'])
                    assert data[:f['byte_start']].count(b'\n')+1 == f['line_start']
                    functions.append(f)
                selected.append({'path': name, 'size': len(data), 'sha256': digest(data),
                                 'functions': functions, 'anchor_lines': original['ascii_anchor_lines']})
                local = WORK / 'oss_selected' / filename / name
                local.parent.mkdir(parents=True, exist_ok=True)
                with local.open('xb') as out:
                    out.write(data)
                found[name] = True
        assert found.keys() == targets.keys(), (filename, targets.keys()-found.keys())
        reports[filename] = {'archive': actual, 'official_url': prior['source_url'],
                             'source_model_label': prior['source_model_label'],
                             'current_method': 'whole archive SHA-256 plus selected exact source/function span checks; no full scan rerun',
                             'selected_sources': selected,
                             'historical_scan_reused': {k: prior[k] for k in
                               ('regular_files', 'regular_bytes', 'nonregular_members_not_scanned', 'patterns', 'hit_counts')},
                             'historical_scan_method': 'All regular tar member bytes; no nested archive/CHM decompression; lexical patterns only'}
    # Do not turn lexical call tokens into a linked or runtime call graph.
    functions = [(a, s['path'], f) for a, r in reports.items()
                 for s in r['selected_sources'] for f in s['functions']]
    adjacency = []
    for archive, path, f in functions:
        adjacency.append({'archive': archive, 'path': path, 'function': f['name'],
                          'line': f['line_start'], 'span_sha256': f['span_sha256'],
                          'lexical_callees': f['lexical_call_tokens'],
                          'lexical_callers_in_selected_functions':
                            [{'path': pp, 'function': ff['name'], 'line': ff['line_start']}
                             for aa,pp,ff in functions if aa==archive and f['name'] in ff['lexical_call_tokens']]})
    save(RESULTS/'oss_boundary.json', {'historical_commit': '3362325de9e36e067f1826575f0fffde24ed98fd',
         'historical_source_audit_id': file_id(oldpath), 'archives': reports, 'function_index': adjacency,
         'verified_boundary': 'These functions consume already-present gzip/Image/RAM blocks or IPC filesystem requests. No actual modern UPD receiver/parser has been recovered here.',
         'limitations': old['boundaries'], 'historical_ver1_to_ver2': old['ver1_to_ver2']})
    print('PASS: 6 exact OSS archives; selected function spans', len(functions),
          '; whole scans reused with explicit historical attribution')

if __name__ == '__main__':
    main()
