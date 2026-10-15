"""Check public artifacts only; does not require or execute vendor samples."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
 manifest=json.loads((HERE/'delivery_manifest.json').read_text(encoding='utf-8'))
 for row in manifest['files']:
  p=(HERE/row['path']).resolve()
  assert p.is_relative_to(HERE.resolve()) and p.is_file(),row['path']
  data=p.read_bytes()
  assert len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256'],row['path']
 print('PASS:',len(manifest['files']),'public artifacts SHA-256 verified; no vendor inputs executed')
if __name__=='__main__':main()
