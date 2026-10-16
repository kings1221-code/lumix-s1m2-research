"""Prove one shared R8 Callable discriminator; never infer ownership from its name."""
import importlib.util
from common import *
def main():
    rows=jsonl(WORK/'dispatch_instructions.jsonl');sem=jsonl(WORK/'semantic_instructions.jsonl')
    edit=next(r for r in rows if 'EditActivity;->E0(' in r['method'])
    by={i['offset_cu']:i for i in edit['instructions']}
    assert by[2]['registers']==[2] and by[2]['literal']==1
    assert by[0x1ad]['registers']==[0,2,3,5]
    # No destination writes to selector v2 between definition and constructor.
    setters=('move','const','iget','sget','aget','new','add','sub','mul','div','rem','and','or','xor','shl','shr','ushr','int','long','float','double','neg','not','array-length','instance-of','cmp')
    assert not [i for i in edit['instructions'] if 2<i['offset_cu']<0x1ad and i['registers'] and i['registers'][0]==2 and i['opcode'].startswith(setters)]
    call=next(r for r in sem if r['method'].startswith('Lg5/k;->call'))
    payload=next(i for i in call['instructions'] if i['offset_cu']==1118)
    case=next(e for e in payload['switch_elements'] if e['key']==1)
    assert 5+case['relative_target_cu']==0xe7
    merge=next(i for i in call['instructions'] if i['offset_cu']==0x213)
    assert 'mergeCubeFiles' in merge['reference']
    spec=importlib.util.spec_from_file_location('offsets',ROOT/'analysis/lab_stage1_20261015/dex_offsets.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    locations={n:module.offsets(SOURCE/'extracted/base'/n) for n in ('classes.dex','classes2.dex')}
    evidence=[]
    for r in rows:
        loc=locations[r['dex']][r['method']];assert r['code_units']==loc['code_units']
        raw=(SOURCE/'extracted/base'/r['dex']).read_bytes()
        selected=[]
        for i in r['instructions']:
            if ('EditActivity;->E0(' in r['method'] and (i['offset_cu']==2 or 0x1a7<=i['offset_cu']<=0x1b0)) or r['method'].startswith('Lg5/k;-><init>'):
                at=loc['insns_offset']+2*i['offset_cu'];selected.append({**i,'file_offset':at,'raw_hex':raw[at:at+2*i['width_cu']].hex()})
        evidence.append({'method':r['method'],'dex':r['dex'],'location':loc,'instructions':selected,
                         'call_sites_to_shared_constructor':[c for c in r['calls'] if c['reference'].startswith('Lg5/k;-><init>')]})
    save(RESULTS/'callable_case_evidence.json',{'methods':evidence,'dispatch':{'method':call['method'],'switch_cu':5,'payload_cu':1118,'selector_1_entry_cu':0xe7,'merge_call_cu':0x213},
         'verified_relation':'EditActivity.E0 constructs g5/k with selector=1; its matching Callable case contains the native merge call. This is conditional execution, not every E0 invocation.',
         'limits':'The same merged class also serves Lottie/other cases. Class-wide callee lists cannot be applied to all constructor callers.'})
    print('PASS: 6 dispatcher method offsets; selector=1 and matching merge case verified')
if __name__=='__main__':main()
