import gzip,hashlib,json,os
from pathlib import Path
BASE=Path(__file__).resolve().parent.parent
ROOT=BASE.parents[1]
PREV=ROOT/'analysis/lumix_lab_full_reverse'
WORK=Path(os.environ.get('LUMIX_DF_WORK',ROOT/'.research-local/lab_df_20261017'))
RESULTS=Path(os.environ.get('LUMIX_DF_RESULTS',BASE/'results'))
SOURCE=Path(os.environ['LUMIX_LAB_SOURCE_ROOT']) if 'LUMIX_LAB_SOURCE_ROOT' in os.environ else Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])
def load(p):
    p=Path(p)
    with (gzip.open(p,'rt',encoding='utf-8') if p.name.endswith('.gz') else p.open(encoding='utf-8')) as f:return json.load(f)
def rows(p):
    with Path(p).open(encoding='utf-8') as f:return [json.loads(line) for line in f]
def sha(b):return hashlib.sha256(b).hexdigest()
def identity(p):
    h=hashlib.sha256();size=0
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b);size+=len(b)
    return {'size':size,'sha256':h.hexdigest()}
def save(p,x,compressed=False):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    b=(json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode()
    if compressed:b=gzip.compress(b,mtime=0)
    if p.exists():assert p.read_bytes()==b, 'Different evidence exists: '+str(p)
    else:
        with p.open('xb') as f:f.write(b)
def namespace(desc):
    if desc.startswith('Lcom/panasonic/'):return 'Panasonic namespace'
    for prefix in ('Lcom/google/','Lcom/adobe/','Lorg/','Landroidx/','Lai/onnxruntime/','Lio/','Lkotlin','Lwseemann/','Lcom/techor/','Ljp/co/cyberagent/'):
        if desc.startswith(prefix):return 'declared third-party namespace: '+prefix
    return 'obfuscated/other; ownership needs code evidence'
def methods():return rows(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
