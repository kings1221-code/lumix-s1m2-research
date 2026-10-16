"""Query public structural metadata without APKs or executing vendor code."""
import argparse
import gzip
from pathlib import Path
import json
BASE=Path(__file__).resolve().parent.parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--method',required=True);a=p.parse_args()
    with gzip.open(BASE/'results/dex_structure.json.gz','rt',encoding='utf-8') as f:x=json.load(f)
    ids={m['id']:m for m in x['methods']};matches={m['id'] for m in x['methods'] if a.method in m['method']}
    for i in sorted(matches):
        print(json.dumps(ids[i],ensure_ascii=False))
        name=ids[i]['method']
        for caller,cu,target,opcode in x['invoke_edges']:
            t=x['call_targets'][target]
            if caller==i:print('CALLEE',hex(cu),opcode,t)
            if t==name:print('CALLER',ids[caller]['method'],hex(cu),opcode)
if __name__=='__main__':main()
