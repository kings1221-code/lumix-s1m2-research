"""Verify public delivery bytes only; no private configuration or samples required."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent

def main():
    manifest=json.loads((HERE/'delivery_manifest.json').read_text(encoding='utf-8'))
    assert manifest['scope']=='public artifacts only; excludes this manifest and ignored local outputs'
    for r in manifest['files']:
        path=(HERE/r['path']).resolve()
        assert path.is_relative_to(HERE) and path.is_file(),r['path']
        b=path.read_bytes()
        assert len(b)==r['size'] and hashlib.sha256(b).hexdigest()==r['sha256'],r['path']
    print('PASS:',len(manifest['files']),'public artifact hashes; no vendor inputs or target execution')

if __name__=='__main__':main()
