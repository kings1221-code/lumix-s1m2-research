"""Public artifact consistency only; no vendor samples or private config required."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    x=json.loads((HERE/'delivery_manifest.json').read_text(encoding='utf-8'))
    for r in x['files']:
        p=(HERE/r['path']).resolve();assert p.is_relative_to(HERE) and p.is_file(),r['path']
        b=p.read_bytes();assert len(b)==r['size'] and hashlib.sha256(b).hexdigest()==r['sha256'],r['path']
    print('PASS:',len(x['files']),'public D/F artifact SHA-256 hashes; no original samples needed')
if __name__=='__main__':main()
