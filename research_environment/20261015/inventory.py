#!/usr/bin/env python3
"""Read-only Lab input inventory. Hash files/ZIP members; never import vendor code."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile


def digest_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def lab_path(path):
    value = path.lower()
    return any(token in value for token in (
        'lumix_lab', 'lumixlab', 'analysis/lab_', '/06_lab_control/',
        '/07_lab_bluetooth/', '/08_lab_preview/', '/lab_client_verification'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extra-root', action='append', type=Path, default=[])
    parser.add_argument('--output', type=Path, required=True, help='New JSON file outside the checkout')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(root):
        parser.error('Output must be a new file outside the repository')

    def load(name):
        return json.loads((root/name).read_text())

    def git(*argv):
        return subprocess.check_output(['git', '-C', str(root), *argv], text=True).strip()

    # Explicit roots only; do not inspect credentials, home directories or Git objects.
    indexed = defaultdict(list)
    roots = [root, *args.extra_root]
    for base in roots:
        if not base.is_dir():
            raise FileNotFoundError(base)
        def inaccessible(error):
            raise error
        for directory, folders, files in os.walk(base, followlinks=False, onerror=inaccessible):
            folders[:] = [f for f in folders if f not in {'.git', '__pycache__', '.venv'}]
            for name in files:
                path = Path(directory)/name
                if path.is_file() and not path.is_symlink():
                    indexed[name].append(path)

    with (root/'evidence/FILE_MANIFEST.csv').open(newline='') as stream:
        manifest = {row['path']: row for row in csv.DictReader(stream)}
    tracked = git('ls-files', '-z').split('\0')
    public = []
    for name in sorted(n for n in tracked if lab_path(n)):
        path = root/name
        reference = manifest.get(name, {})
        actual = digest_file(path)
        expected = reference.get('public_sha256')
        status = ('verified_public_sha256' if expected == actual else
                  'checksum_mismatch' if expected else 'present_without_manifest_reference')
        public.append({'path': name, 'bytes': path.stat().st_size, 'sha256': actual,
                       'expected_public_sha256': expected, 'status': status,
                       'publication_status': reference.get('status')})

    raw = []
    verified_apks = {}

    def record_file(name, size, expected, source, kind):
        candidates = []
        for path in indexed[name]:
            actual = digest_file(path)
            candidates.append({'path': str(path), 'bytes': path.stat().st_size, 'sha256': actual,
                               'matches_reference': actual == expected and path.stat().st_size == size})
        matches = [row for row in candidates if row['matches_reference']]
        if matches and name.endswith('.apk'):
            verified_apks[name] = Path(matches[0]['path'])
        raw.append({'name': name, 'kind': kind, 'expected_bytes': size,
                    'expected_sha256': expected, 'reference': source, 'candidates': candidates,
                    'status': 'verified_input_sha256' if matches else
                              'checksum_mismatch' if candidates else 'missing_historical_input'})

    acquisition = load('analysis/lumix_lab_acquisition_gemini_20261008.json')
    source = 'analysis/lumix_lab_acquisition_gemini_20261008.json'
    bundle = acquisition['downloaded_files']['bundle_xapk']
    record_file(Path(bundle['path']).name, bundle['size_bytes'], bundle['sha256'], source, 'xapk')
    for item in acquisition['downloaded_files']['components']:
        if item['filename'].endswith('.apk'):
            record_file(item['filename'], item['size_bytes'], item['sha256'], source, item['type'])

    def record_member(apk, entry, size, expected, reference, kind):
        candidates = []
        if apk in verified_apks:
            with zipfile.ZipFile(verified_apks[apk]) as archive:
                info = archive.getinfo(entry)
                with archive.open(entry) as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                candidates.append({'path': str(verified_apks[apk])+'!/'+entry,
                                   'bytes': info.file_size, 'sha256': actual})
        for path in indexed[Path(entry).name]:
            candidates.append({'path': str(path), 'bytes': path.stat().st_size,
                               'sha256': digest_file(path)})
        matches = [row for row in candidates if row['bytes'] == size and row['sha256'] == expected]
        raw.append({'name': entry, 'kind': kind, 'parent_apk': apk, 'expected_bytes': size,
                    'expected_sha256': expected, 'reference': reference, 'candidates': candidates,
                    'status': 'verified_input_sha256' if matches else
                              'present_without_reference_sha256' if candidates and not expected else
                              'checksum_mismatch' if candidates else 'missing_historical_input'})

    dex = load('analysis/agy_takeover_20261012/07_lab_bluetooth/dex_verification.json')
    record_member('com.panasonic.jp.lumixlab.apk', 'classes.dex', 7341852, None,
                  'analysis/lumix_lab_code_strings_codex_20261008.json (size only)', 'dex')
    record_member('com.panasonic.jp.lumixlab.apk', dex['dex_name'], dex['dex_size_bytes'],
                  dex['dex_sha256'], 'analysis/agy_takeover_20261012/07_lab_bluetooth/dex_verification.json', 'dex')
    native_source = 'analysis/lab_crypto_callsite_audit_20261010/native_symbols.json'
    for item in load(native_source)['libraries']:
        record_member('config.arm64_v8a.apk', item['entry'], item['size'], item['sha256'], native_source, 'arm64_library')

    source_reference = 'analysis/project_corrections_20261014/source_reports/lab_client_verification_final.json'
    source_files = []
    source_base = root/'analysis/sources/lumix_lab_codex_static/decompiled/sources'
    for name, reference in load(source_reference)['cited_source_files'].items():
        path = source_base/name
        actual = digest_file(path) if path.is_file() else None
        source_files.append({'path': str(path.relative_to(root)), 'expected_sha256': reference['sha256'],
                             'sha256': actual, 'status': 'missing_historical_input' if actual is None else
                             'verified_input_sha256' if actual == reference['sha256'] else 'checksum_mismatch'})

    fork = []
    for ref in git('for-each-ref', '--format=%(refname:short)', 'refs/remotes/origin').splitlines():
        left, right = map(int, git('rev-list', '--left-right', '--count', ref+'...upstream/main').split())
        fork.append({'ref': ref, 'commit': git('rev-parse', ref),
                     'fork_only_commits': left, 'upstream_only_commits': right})
    report = {
        'scope': 'offline inventory and static preparation; no vendor execution or device access',
        'search_roots': list(map(str, roots)),
        'upstream_commit': git('rev-parse', 'upstream/main'),
        'fork_main_commit': git('rev-parse', 'origin/main'), 'fork_branches': fork,
        'public_lab_artifacts': public,
        'raw_lab_inputs': raw, 'full_decompiled_sources_for_corrected_report': source_files,
        'counts': {'public': dict(Counter(row['status'] for row in public)),
                   'raw': dict(Counter(row['status'] for row in raw)),
                   'decompiled_sources': dict(Counter(row['status'] for row in source_files))},
        'limitations': [
            'Public hashes verify archive bytes, not historical raw APK/DEX/native correctness.',
            'Historical APKPure distribution identity remains unverified; redacted signer metadata cannot authenticate a publisher.',
            'classes.dex has a historical size but no independent member SHA-256 in the selected source records.',
            'Native dynamic symbols and decompiler excerpts cannot replace original binaries or complete DEX control flow.',
            'No full source regeneration or new large reverse-engineering analysis was performed.'
        ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(report['counts']))
    if any(row['status'] == 'checksum_mismatch' for row in public+raw+source_files):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
