from common import *
def main():
    idx=jsonl(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
    targets=[r['method'] for r in idx if r['method'].startswith('Lg5/k;-><init>') or any(c['reference'].startswith('Lg5/k;-><init>') for c in r['calls'])]
    with (WORK/'dispatch_targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(targets)+'\n')
    print('Prepared',len(targets),'shared Callable constructor/caller methods')
if __name__=='__main__':main()
