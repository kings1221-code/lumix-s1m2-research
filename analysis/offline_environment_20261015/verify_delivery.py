"""Verify the exact LF artifact bytes delivered on this research branch."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    manifest = json.loads((HERE / 'delivery_manifest.json').read_text(encoding='utf-8'))
    failures = []
    for row in manifest['files']:
        path = (HERE / row['path']).resolve()
        if not path.is_relative_to(HERE):
            raise SystemExit('Manifest path outside research directory')
        if not path.is_file() or path.stat().st_size != row['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            failures.append(row['path'])
    if failures:
        raise SystemExit('FAIL: ' + ', '.join(failures))
    print(f"PASS: {len(manifest['files'])} delivered artifacts match exact SHA-256; no targets executed")


if __name__ == '__main__':
    main()
