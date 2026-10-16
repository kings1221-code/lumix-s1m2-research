"""Verify this stage's public Git artifact bytes only, without vendor inputs."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent

def main():
    manifest=json.loads((HERE/'delivery_manifest.json').read_text(encoding='utf-8'))
    for r in manifest['files']:
        path=(HERE/r['path']).resolve()
        assert path.is_relative_to(HERE.resolve())
        b=path.read_bytes()
        assert len(b)==r['size'] and hashlib.sha256(b).hexdigest()==r['sha256'],r['path']
    print('PASS:',len(manifest['files']),'public artifacts; no vendor inputs required or executed')

if __name__=='__main__':
    main()
