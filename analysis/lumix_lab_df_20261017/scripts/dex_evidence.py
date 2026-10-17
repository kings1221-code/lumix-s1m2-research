"""Independent raw DEX method_ids and invoke operands, not JADX text as evidence."""
import importlib.util,struct
from common import *
def uleb(b,p):
    n=0;s=0
    while True:
        v=b[p];p+=1;n|=(v&127)<<s
        if v<128:return n,p
        s+=7
def tables(b):
    strings={};sn,so=struct.unpack_from('<II',b,56);tn,to=struct.unpack_from('<II',b,64);pn,po=struct.unpack_from('<II',b,72);mn,mo=struct.unpack_from('<II',b,88)
    def text(i):
        if i not in strings:
            off=struct.unpack_from('<I',b,so+4*i)[0];_,p=uleb(b,off);end=b.index(0,p)
            strings[i]=b[p:end].replace(b'\xc0\x80',b'\0').decode('utf-8',errors='surrogatepass')
        return strings[i]
    def typ(i):return text(struct.unpack_from('<I',b,to+4*i)[0])
    out=[]
    for i in range(mn):
        cl,pr,name=struct.unpack_from('<HHI',b,mo+8*i);shorty,ret,params=struct.unpack_from('<III',b,po+12*pr)
        ps='' if params==0 else ''.join(typ(struct.unpack_from('<H',b,params+4+2*j)[0]) for j in range(struct.unpack_from('<I',b,params)[0]))
        out.append(typ(cl)+'->'+text(name)+'('+ps+')'+typ(ret))
    return out,text
def main():
    spec=importlib.util.spec_from_file_location('offsets',ROOT/'analysis/lab_stage1_20261015/dex_offsets.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    names=('classes.dex','classes2.dex');blobs={n:(SOURCE/'extracted/base'/n).read_bytes() for n in names}
    loc={n:module.offsets(SOURCE/'extracted/base'/n) for n in names};tabs={n:tables(blobs[n]) for n in names}
    inherited=rows(ROOT/'.research-local/full_reverse/dispatch_instructions.jsonl')
    inherited+=[m for m in rows(ROOT/'.research-local/full_reverse/semantic_instructions.jsonl') if m['method'].startswith('Lg5/k;->call(')]
    review=rows(WORK/'review_instructions.jsonl')
    raw=rows(WORK/'instructions.jsonl')+rows(WORK/'extra_instructions.jsonl')+inherited+review;seen=set();meta=[];calls=[];constants=[]
    case_methods={m['method'] for m in inherited+review}
    dynamic={r['caller'] for r in load(RESULTS/'dynamic_seed.json')['candidates']}
    api={(r['method'],r['cu']) for r in load(RESULTS/'api_usage.json.gz')['sites']}
    additional=load(RESULTS/'firmware_dynamic_scope.json.gz')['additional_dynamic_sites'];extra={(r['caller'],r['cu']) for r in additional}
    for m in raw:
        if m['method'] in seen:continue
        seen.add(m['method']);l=loc[m['dex']][m['method']];b=blobs[m['dex']];table,text=tabs[m['dex']]
        assert l['code_units']==m['code_units'] and sum(i['width_cu'] for i in m['instructions'])==m['code_units']
        body=b[l['insns_offset']:l['insns_offset']+2*l['code_units']] if l['insns_offset'] is not None else b''
        meta.append({'method':m['method'],'dex':m['dex'],'location':l,'instruction_sha256':sha(body)})
        for i in m['instructions']:
            at=l['insns_offset']+2*i['offset_cu'];op=b[at]
            if i['opcode'].startswith('invoke-') and 'reference' in i and '->' in i['reference']:
                assert op in tuple(range(0x6e,0x73))+tuple(range(0x74,0x79))+(0xfa,0xfb)
                mid=struct.unpack_from('<H',b,at+2)[0];assert table[mid]==i['reference'],(m['method'],i)
                if op in (0x74,0x75,0x76,0x77,0x78,0xfb):
                    n=b[at+1];start=struct.unpack_from('<H',b,at+4)[0];regs=list(range(start,start+n))
                else:
                    n=b[at+1]>>4;last=b[at+1]&15;packed=struct.unpack_from('<H',b,at+4)[0];regs=[(packed>>(4*j))&15 for j in range(4)]+[last];regs=regs[:n]
                assert regs==i['registers']
                if (m['method'],i['offset_cu']) in api or (m['method'],i['offset_cu']) in extra or m['method'] in dynamic or m['method'] in case_methods:
                    calls.append({'method':m['method'],'dex':m['dex'],'cu':i['offset_cu'],'file_offset':at,'opcode':i['opcode'],'registers':regs,'target':table[mid],'raw_hex':b[at:at+2*i['width_cu']].hex()})
            if m['method'] in dynamic and i['opcode'].startswith('const-string'):
                sid=struct.unpack_from('<H' if op==0x1a else '<I',b,at+2)[0];assert text(sid)==i['reference']
                constants.append({'method':m['method'],'dex':m['dex'],'cu':i['offset_cu'],'file_offset':at,'string_id':sid,'value_sha256':sha(i['reference'].encode('utf-8',errors='surrogatepass')),'raw_hex':b[at:at+2*i['width_cu']].hex()})
    assert api<={(r['method'],r['cu']) for r in calls}
    save(RESULTS/'selected_dex_evidence.json.gz',{'inputs':[{'dex':n,**identity(SOURCE/'extracted/base'/n)} for n in names],'methods':meta,'invoke_operands_checked':calls,'dynamic_string_operands_checked_without_values':constants,
         'method':'Independent DEX header/type/proto/method_ids parsing and 35c/3rc register decoding, original code_item offsets, raw instruction bytes. Full target code remains private.'},True)
    print('PASS:',len(meta),'unique selected bodies;',len(calls),'published invoke operand checks;',len(constants),'dynamic string operands')
if __name__=='__main__':main()
