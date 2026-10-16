"""Verify saved stage 1 deliverables, actual log events, JNI counts and all inputs.
Does not repeat decompilation, native scans or Ghidra analysis.
"""
import collections
import gzip
import json
from pathlib import Path
from common import ROOT, WORK, RESULTS, digest, file_id, save, git, load, config

def main():
    stage1 = ROOT / 'analysis/lab_stage1_20261015'
    manifest = load(stage1 / 'delivery_manifest.json')
    checked = []
    for row in manifest['files']:
        p = stage1 / row['path']
        actual = file_id(p)
        assert actual == {k: row[k] for k in ('size', 'sha256')}, row['path']
        checked.append({'path': row['path'], **actual})
    source = Path(config()['source_root'])
    inputs = load(stage1 / 'results/inputs.json')['input_files']
    for row in inputs:
        if row['kind'] == 'APK':
            p = Path(row['path_token'].replace('<SOURCE_ROOT>', str(source)))
        elif row['kind'] == 'DEX':
            p = source / 'extracted/base' / row['member']
        else:
            p = source / 'extracted/arm64' / row['member']
        assert file_id(p) == {k: row[k] for k in ('size', 'sha256')}, str(p)
    log = ROOT / '.research-local/stage1/jadx_replay.log'
    failures = load(stage1 / 'results/jadx_failures.json')
    events = [line for line in log.read_text(encoding='utf-8', errors='replace').splitlines()
              if 'ERROR' in line and ' in method: ' in line]
    # All saved method labels must occur in the actual replay log.
    assert len(events) == 42, len(events)
    assert len(failures['methods']) == 24
    actual_labels={line.split(' in method: ',1)[1].split(', file:',1)[0] for line in events}
    assert actual_labels == {m['jadx_label'] for m in failures['methods']}
    for m in failures['methods']:
        assert any(m['jadx_label'] in line for line in events), m['method']
    cfg = load(stage1 / 'results/failed_method_cfg_index.json')
    mapping = load(stage1 / 'results/jni_mapping_verified.json')
    scope = load(stage1 / 'results/scope_verification.json')
    with gzip.open(stage1 / 'results/failed_method_cfg.json.gz', 'rb') as f:
        cfg_bytes = f.read()
    assert digest(cfg_bytes) == cfg['uncompressed_sha256']
    assert len(cfg['methods']) == 24
    jni_counts = dict(collections.Counter(r['status'] for r in mapping['mapping']))
    assert sum(jni_counts.values()) == 214 and jni_counts == scope['jni_status']
    result = {'stage1_commit': '69333e24675fcdbe2f7d00481a3360af78a1ea9e',
              'stage1_remote_commit': git('rev-parse', 'origin/codex/lumix-lab-stage1-20261015').decode().strip(),
              'stage1_public_files_checked': checked,
              'input_files_rechecked': inputs,
              'jadx_log': file_id(log), 'actual_error_events': len(events),
              'distinct_failed_methods': len(failures['methods']),
              'structural_cfg_uncompressed_sha256': digest(cfg_bytes),
              'cfg_index': cfg,
              'jni_saved_scope': scope,
              'jni_counts_recomputed_from_214_rows': jni_counts,
              'jni_mapping_sha256': file_id(stage1 / 'results/jni_mapping_verified.json'),
              'git_start': {'head': git('rev-parse', 'HEAD').decode().strip(),
                            'branch': git('branch', '--show-current').decode().strip(),
                            'fork_main': git('rev-parse', 'origin/main').decode().strip(),
                            'upstream_main': git('rev-parse', 'upstream/main').decode().strip(),
                            'status': git('status', '--short').decode('utf-8', errors='replace')},
              'scope': 'Hash checks and actual saved log verification; no decompilation/scanning repeated'}
    assert result['stage1_remote_commit'] == result['stage1_commit']
    save(RESULTS / 'stage1_preservation.json', result)
    print('PASS: stage1 public files', len(checked), '; original inputs', len(inputs),
          '; actual error events', len(events), '; distinct methods', len(failures['methods']))

if __name__ == '__main__':
    main()
