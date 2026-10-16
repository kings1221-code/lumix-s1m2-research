"""Select new semantic questions, retaining prior failed-method instruction streams."""
from common import *
def main():
    idx=jsonl(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
    prefixes=('Lcom/google/android/gms/tasks/NativeOnCompleteListener;', 'Ll0/h;->D(', 'Ll0/h;->L(', 'Ll0/h;->M(', 'Ll0/h;-><clinit>', 'Ll0/i;->d(', 'Ll0/i;->e(', 'Ll0/c;->b(', 'Lg5/k;->call(')
    selected=[r['method'] for r in idx if r['method'].startswith(prefixes)]
    with (WORK/'semantic_targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(sorted(selected))+'\n')
    print('Selected',len(selected),'semantic methods; previous 24 CFGs retained')
if __name__=='__main__':main()
