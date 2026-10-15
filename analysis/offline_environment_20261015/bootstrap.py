"""Install only SHA-256 locked official tools into .research-local; no targets run."""
import argparse
import hashlib
import json
import shutil
import urllib.request
import venv
import zipfile
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCAL = ROOT / '.research-local'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, help='Read-only existing official archive cache')
    parser.add_argument('--allow-download', action='store_true', help='Fetch pinned official HTTPS URLs')
    args = parser.parse_args()
    cache = LOCAL / 'downloads'
    cache.mkdir(parents=True, exist_ok=True)
    records = []
    for item in json.loads((HERE / 'toolchain.lock.json').read_text())['tools']:
        target = cache / item['filename']
        source = args.cache / item['filename'] if args.cache else None
        if not target.exists():
            if source and source.is_file():
                if digest(source) != item['sha256']:
                    raise SystemExit(f'Refuse mismatching existing archive: {source.name}')
                shutil.copyfile(source, target)
            elif args.allow_download:
                if urlparse(item['url']).scheme != 'https' or urlparse(item['url']).hostname not in {'github.com', 'files.pythonhosted.org'}:
                    raise SystemExit('Refuse unapproved origin')
                partial = target.with_suffix(target.suffix + '.partial')
                # Exclusive create: never overwrite a partial download or existing work.
                with urllib.request.urlopen(item['url'], timeout=60) as response, partial.open('xb') as output:
                    shutil.copyfileobj(response, output)
                if digest(partial) != item['sha256']:
                    raise SystemExit(f'Download hash mismatch: {target.name}; partial retained')
                partial.rename(target)
            else:
                raise SystemExit(f'Missing official archive: {target.name}; provide cache or --allow-download')
        if digest(target) != item['sha256'] or ('size' in item and target.stat().st_size != item['size']):
            raise SystemExit(f'Archive verification failed: {target.name}')
        records.append({'id': item['id'], 'sha256': digest(target), 'verified_official_lock': True})
        if target.suffix == '.zip':
            destination = LOCAL / 'tools' / item['id']
            marker = destination / '.verified-archive-sha256'
            if destination.exists():
                if not marker.is_file() or marker.read_text() != item['sha256']:
                    raise SystemExit(f'Refuse existing unverified extraction: {destination.name}')
                # Check all installed members against the locked archive before reuse.
                with zipfile.ZipFile(target) as archive:
                    for entry in archive.infolist():
                        if not entry.is_dir():
                            installed = destination / entry.filename
                            with archive.open(entry) as src:
                                expected = hashlib.file_digest(src, 'sha256').hexdigest()
                            if not installed.is_file() or digest(installed) != expected:
                                raise SystemExit(f'Installed tool changed: {entry.filename}')
            else:
                destination.mkdir(parents=True)
                with zipfile.ZipFile(target) as archive:
                    for entry in archive.infolist():
                        resolved = (destination / entry.filename).resolve()
                        if not resolved.is_relative_to(destination.resolve()):
                            raise SystemExit('Unsafe archive path')
                    archive.extractall(destination)
                marker.write_text(item['sha256'])
    environment = LOCAL / 'venv'
    if not (environment / 'Scripts/python.exe').exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    (LOCAL / 'bootstrap-verification.json').write_text(json.dumps(records, indent=2) + '\n')
    print('PASS: 4 official tool archives SHA-256 verified; portable tools and venv prepared')


if __name__ == '__main__':
    main()
