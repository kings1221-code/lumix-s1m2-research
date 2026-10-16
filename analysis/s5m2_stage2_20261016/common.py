"""Stage 2 read-only evidence helpers. No network or target execution."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = Path(os.environ.get('LUMIX_STAGE2_WORK', ROOT / '.research-local/stage2')).resolve()
RESULTS = Path(os.environ.get('LUMIX_STAGE2_RESULTS', HERE / 'results')).resolve()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_id(path):
    h = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(b)
            size += len(b)
    return {'size': size, 'sha256': h.hexdigest()}

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def config():
    return load(WORK / 'paths.json')
