"""Query public API index; requires neither original APK nor private configuration."""
import argparse,gzip,json
from pathlib import Path
BASE=Path(__file__).resolve().parent.parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--method',default='');p.add_argument('--api',default='');p.add_argument('--limit',type=int,default=30);a=p.parse_args()
    with gzip.open(BASE/'results/api_usage.json.gz','rt',encoding='utf-8') as f:x=json.load(f)
    found=[r for r in x['sites'] if a.method in r['method'] and a.api in r['target']]
    print('matching sites:',len(found))
    for r in found[:a.limit]:print(json.dumps(r,ensure_ascii=False))
if __name__=='__main__':main()
