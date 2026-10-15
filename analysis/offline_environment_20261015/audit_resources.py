"""Read-only resource identity audit. Never imports or executes APK/DEX/ELF contents."""
import argparse
import base64
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path, expected=None, expected_size=None):
    row = {'expected_sha256': expected, 'expected_size': expected_size}
    if not path.is_file():
        return row | {'status': 'missing'}
    actual = sha(path)
    good = (not expected or actual == expected.lower()) and (expected_size is None or path.stat().st_size == expected_size)
    return row | {'sha256': actual, 'size': path.stat().st_size,
                  'status': ('verified_sha256_reference' if expected else 'present_without_prior_reference') if good else 'mismatch'}


def member_audit(archive, member, extracted):
    with archive.open(member) as stream:
        expected = hashlib.file_digest(stream, 'sha256').hexdigest()
    row = {'member': member, **identity(extracted, expected, archive.getinfo(member).file_size)}
    data = archive.read(member) if member.endswith('.dex') else None
    if data is not None:
        row['dex_header'] = {'magic': data[:8].hex(), 'file_size_matches': struct.unpack_from('<I', data, 32)[0] == len(data),
                             'header_sha1_matches': hashlib.sha1(data[32:]).digest() == data[12:32],
                             'adler32_matches': zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from('<I', data, 8)[0]}
    elif member.endswith('.so'):
        with archive.open(member) as stream:
            header = stream.read(64)
        row['elf_header'] = {'magic_matches': header[:4] == b'\x7fELF', 'class': header[4],
                             'endianness': header[5], 'e_machine': struct.unpack_from('<H', header, 18)[0],
                             'arm64': header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == 183}
    return row


def public_records():
    references = {}
    for name, key in [('FILE_MANIFEST.csv', 'path'), ('CORRECTION_INPUTS_20261014.csv', 'published_path')]:
        with (ROOT / 'evidence' / name).open(encoding='utf-8', newline='') as stream:
            for row in csv.DictReader(stream):
                if row.get(key) and row.get('public_sha256'):
                    references[row[key]] = (row['public_sha256'], name)
    records = []
    for path, (expected, manifest) in sorted(references.items()):
        if not (('lab' in path.lower() and path.startswith(('analysis/', 'docs/'))) or path in {
            'README.md', 'S1M2研究当前状态.md', 'docs/REPRODUCE_20261013.md', 'docs/PROJECT_CORRECTIONS_20261014.md',
            'analysis/project_corrections_20261014/source_reports/lab_client_verification_final.json'}):
            continue
        row = {'path': path, 'manifest': manifest, **identity(ROOT / path, expected)}
        blob = subprocess.check_output(['git', 'show', 'HEAD:' + path], cwd=ROOT)
        row['git_blob_sha256'] = hashlib.sha256(blob).hexdigest()
        if row['status'] == 'mismatch' and row['git_blob_sha256'] == expected:
            raw = (ROOT / path).read_bytes()
            if raw.replace(b'\r\n', b'\n') == blob:
                row['status'] = 'verified_git_blob_worktree_crlf'
        records.append(row)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='Must not exist')
    parser.add_argument('--firmware', action='append', type=Path, default=[])
    parser.add_argument('--s1m2', type=Path, help='Optional exact S1M2 V1.4 BIN for SHA-256 inventory only')
    args = parser.parse_args()
    source = args.source_root.resolve()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(source):
        raise SystemExit('Output must be new and outside source tree')
    output.mkdir(parents=True)
    integrity = source / 'apk/integrity.json'
    reference_copy = HERE / 'references/google-play-delivery-integrity.json'
    result = {'scope': 'offline_identity_and_headers_only', 'target_execution': False,
              'source_path_token': '<SOURCE_ROOT>', 'reference_metadata': {'path': 'apk/integrity.json', **identity(integrity, sha(reference_copy))},
              'provenance_limit': 'Local Google Play delivery record is historical metadata; no fresh store or APK signature attestation.',
              'apks': [], 'dex': [], 'native': [], 'selected_corrected_sources': [], 'local_reports': []}
    for item in json.loads(reference_copy.read_text(encoding='utf-8'))['files']:
        expected = base64.urlsafe_b64decode(item['digest'] + '=' * (-len(item['digest']) % 4)).hex()
        result['apks'].append({'path': 'apk/' + item['path'], **identity(source / 'apk' / item['path'], expected, item['size'])})
    by_name = {row['path'].split('/')[-1]: row for row in result['apks']}
    base = source / 'apk/com.panasonic.jp.lumixlab-22.apk'
    arm = source / 'apk/com.panasonic.jp.lumixlab-22-config.arm64_v8a.apk'
    # Parse only archives that match their full recorded SHA-256.
    for path, kind, prefix in [(base, 'dex', source / 'extracted/base'), (arm, 'native', source / 'extracted/arm64')]:
        if by_name[path.name]['status'] != 'verified_sha256_reference':
            continue
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise SystemExit('Ambiguous duplicate archive members')
            for member in names:
                if (kind == 'dex' and member.endswith('.dex')) or (kind == 'native' and member.startswith('lib/arm64-v8a/') and member.endswith('.so')):
                    row = member_audit(archive, member, prefix / member)
                    row['container'] = path.name
                    result[kind].append(row)
    correction = json.loads((ROOT / 'analysis/project_corrections_20261014/source_reports/lab_client_verification_final.json').read_text(encoding='utf-8'))
    trees = [source / name / 'sources' for name in ['jadx-output', 'decompiled', 'decompiled-utf8']]
    result['decompiler_trees'] = []
    for tree in trees:
        result['decompiler_trees'].append({'path': str(tree.relative_to(source)), 'java_count': sum(1 for _ in tree.rglob('*.java')),
            'panasonic_java_count': sum(1 for _ in (tree / 'com/panasonic').rglob('*.java'))})
    for relative, evidence in correction['cited_source_files'].items():
        candidates = [tree / relative for tree in trees]
        rows = [{'path': str(p.relative_to(source)), **identity(p, evidence['sha256'], evidence['size_bytes'])} for p in candidates]
        for candidate, row in zip(candidates, rows):
            if row['status'] == 'mismatch':
                normalized = candidate.read_bytes().replace(b'\r\n', b'\n')
                row['normalized_lf_sha256'] = hashlib.sha256(normalized).hexdigest()
                row['normalized_lf_size'] = len(normalized)
                if row['normalized_lf_sha256'] == evidence['sha256'] and len(normalized) == evidence['size_bytes']:
                    row['status'] = 'verified_normalized_lf_reference'
        match = next((row for row in rows if row['status'].startswith('verified_')), None)
        result['selected_corrected_sources'].append({'cited_source': relative, 'reference': '2026-10-14 corrected client evidence',
            'status': match['status'] if match else 'missing_or_different', 'copies': rows})
    for name in ['ANALYSIS.md', 'VERIFICATION.md', 'BREAKTHROUGH.md', 'analysis/signature.txt', 'analysis/AndroidManifest.xml']:
        result['local_reports'].append({'path': name, 'claim_status': 'historical_record_only', **identity(source / name)})
    result['public_evidence'] = public_records()
    result['s1m2_firmware'] = {'name': 'S1m2_V14.bin', **identity(args.s1m2 or source / 'S1m2_V14.bin',
        'e91620854dd435131e03178076b486767cf9a3d2cfd62d173c537cb2afe9ea0f', 171867648)}
    result['missing_historical_inputs'] = [
        {'name': 'Panasonic_LUMIX_Lab_3.1.0_APKPure.xapk', 'size': 235867498, 'sha256': '06e00657ee592870f1de106de0762637a05ee6a7cf91c916b7273305381ae477', 'status': 'missing'},
        {'name': 'config.mdpi.apk', 'size': 2997638, 'sha256': 'c9ef5805000fb77ef3a97e9f5bc3ce730fc77f7db7fe19cb56c9dc1b8fccefbe', 'status': 'missing'},
        {'name': 'S1M2 proprietary plaintext / actual deployment DTB / body daemon / physical RAM', 'status': 'missing', 'sha256': None}]
    result['missing_historical_inputs_scope'] = '2026-10-15 manual filename search snapshot: workspace, user Downloads, Desktop, Documents. XAPK/mdpi and body-side gaps are recorded historical gaps, not an exhaustive disk scan by this script.'
    if result['s1m2_firmware']['status'] != 'verified_sha256_reference':
        result['missing_historical_inputs'].insert(0, result['s1m2_firmware'])
    profiles = json.loads((HERE / 'references/s5m2_corpus_profiles.json').read_text(encoding='utf-8'))['images']
    result['supplementary_firmware'] = []
    for path in args.firmware:
        with zipfile.ZipFile(path) if path.suffix.lower() == '.zip' else path.open('rb') as stream:
            if isinstance(stream, zipfile.ZipFile):
                for entry in stream.infolist():
                    if entry.filename.lower().endswith('.bin'):
                        with stream.open(entry) as content:
                            actual = hashlib.file_digest(content, 'sha256').hexdigest()
                        expected = next((p for p in profiles.values() if p['sha256'] == actual), None)
                        result['supplementary_firmware'].append({'container': path.name, 'container_sha256': sha(path), 'member': entry.filename,
                            'sha256': actual, 'size': entry.file_size, 'status': 'verified_historical_profile' if expected else 'present_without_prior_reference'})
            else:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                expected = next((p for p in profiles.values() if p['sha256'] == actual), None)
                result['supplementary_firmware'].append({'name': path.name, 'sha256': actual, 'size': path.stat().st_size,
                    'status': 'verified_historical_profile' if expected else 'present_without_prior_reference'})
    result['summary'] = {key: dict(Counter(row['status'] for row in result[key])) for key in [
        'apks', 'dex', 'native', 'selected_corrected_sources', 'public_evidence', 'supplementary_firmware']}
    result['historical_replay_complete'] = all(row['status'].startswith('verified_') for row in result['selected_corrected_sources']) and not result['missing_historical_inputs']
    (output / 'inventory.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result['summary'], ensure_ascii=False))
    # Missing originals are a reported gap, while mismatching supplied files fail verification.
    if result['s1m2_firmware']['status'] == 'mismatch' or result['reference_metadata']['status'] == 'mismatch' or any(row['status'] == 'mismatch' for key in ['apks', 'dex', 'native', 'public_evidence'] for row in result[key]):
        raise SystemExit(1)
    if any(not all(row['dex_header'][key] for key in ['file_size_matches', 'header_sha1_matches', 'adler32_matches']) for row in result['dex']) or any(not row['elf_header']['arm64'] for row in result['native']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
