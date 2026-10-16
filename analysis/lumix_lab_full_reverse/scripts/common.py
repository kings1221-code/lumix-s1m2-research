import gzip
import hashlib
import json
import os
from pathlib import Path

BASE=Path(__file__).resolve().parent.parent
ROOT=BASE.parents[1]
WORK=Path(os.environ.get('LUMIX_FULL_WORK',ROOT/'.research-local/full_reverse')).resolve()
RESULTS=Path(os.environ.get('LUMIX_FULL_RESULTS',BASE/'results')).resolve()
SOURCE=Path(os.environ['LUMIX_LAB_SOURCE_ROOT']) if 'LUMIX_LAB_SOURCE_ROOT' in os.environ else Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])

def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def file_id(p):
    h=hashlib.sha256();size=0
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b);size+=len(b)
    return {'size':size,'sha256':h.hexdigest()}
def save(p,x,compressed=False):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    b=(json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    b=gzip.compress(b,mtime=0) if compressed else b
    if p.exists():
        assert p.read_bytes()==b, 'Refusing to overwrite different evidence: '+str(p)
        return
    with p.open('xb') as f:f.write(b)
def jsonl(p):
    with Path(p).open(encoding='utf-8') as f:return [json.loads(s) for s in f]
