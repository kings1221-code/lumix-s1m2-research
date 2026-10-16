"""Select only stage-1 open questions from the saved DEX reference index."""
from common import ROOT, WORK, save
import json

PREFIXES = (
 'LR5/e;', 'LR5/f;', 'LR5/g;', 'LR5/h;',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->v0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->q0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->r0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->w0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->x0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->u0(',
 'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->z0(',
 'Lcom/panasonic/jp/lumixlab/util/E1;->b(',
 'Lcom/panasonic/jp/lumixlab/util/E1;->c(',
 'Lcom/panasonic/jp/lumixlab/util/b0;->A(',
 'Lcom/panasonic/jp/lumixlab/util/b0;->y(',
 'Lcom/panasonic/jp/lumixlab/util/v;->v(',
 'Lz5/j4;->c(', 'Lz5/g4;->run(', 'Lz5/g3;->run(', 'Lz5/i4;->onClick(',
 'Lz5/n4;->onReceive(', 'Lz5/t1;->b(', 'Lz5/k2;->A(',
 'LH5/d;->onCharacteristicChanged(', 'LF5/f;->c(', 'Ld7/a;->apply(',
 'Lg8/y0;', 'Lg8/z0;->a(', 'Loa/o0;',
 'Lm8/a;->a(', 'Lm8/b;->a(', 'Ll8/c;',
 'Ln8/j;->f(', 'Ln8/d;->i(', 'Ln8/h;->i(',
 'Lo8/C;->f(', 'Lo8/H;->i(', 'Lo8/H;->b(', 'Lo8/M;->f(',
 'Lu8/z;->S(', 'Lu8/z;->L(', 'Lu8/z;->close(',
 'Lu8/j;->S(', 'Lu8/j;->h0(', 'Lu8/x;->i(',
 'Lh6/h;->l(', 'Lh6/h;->i(', 'Lh6/g;->a(', 'Lh6/d;->verify(',
 'LI5/c;->d(', 'Lz7/q;->c(',
 'Loa/g;->a(', 'Loa/b;->a(', 'Lu8/o;->i(', 'Lu8/j;->i(',
 'Lo8/H;->a(', 'Lo8/A;->z(', 'Lo8/M;->b(', 'Lo8/K;->g(',
 'LU7/J0;->y(', 'Lu8/c;->i(', 'Ll8/o;->g(',
)

def main():
    with (ROOT/'.research-local/stage1/dex_index_v2.jsonl').open(encoding='utf-8') as f:
        index = [json.loads(line) for line in f]
    targets = sorted(r['method'] for r in index if r['method'].startswith(PREFIXES))
    with (WORK/'android_targets_final.txt').open('x', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(targets)+'\n')
    save(WORK/'selected_reference_metadata_final.json', [r for r in index if r['method'] in targets])
    extra_prefixes=('Lcom/panasonic/jp/lumixlab/util/b0;->M(',
                    'Lcom/panasonic/jp/lumixlab/util/b0;->f(', 'LA1/b;->run(')
    extra=sorted(r['method'] for r in index if r['method'].startswith(extra_prefixes))
    with (WORK/'android_paths_extra.txt').open('x',encoding='utf-8',newline='\n') as f:
        f.write('\n'.join(extra)+'\n')
    print('Selected', len(targets), 'methods from existing index; no full DEX/native scan repeated')

if __name__ == '__main__':
    main()
