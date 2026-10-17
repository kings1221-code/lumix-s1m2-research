"""Resolve the exact 427 IDs using read-only split ARSC + ZIP bytes, not names alone."""
import collections,struct,zipfile,xml.etree.ElementTree as ET
from common import *
def chunks(b,start,end):
    while start<end:
        typ,hdr,size=struct.unpack_from('<HHI',b,start)
        assert size>=hdr>=8 and start+size<=end
        yield start,typ,hdr,size
        start+=size
    assert start==end
def pool(b,at):
    typ,hdr,size=struct.unpack_from('<HHI',b,at);assert typ==1
    count,styles,flags,start,style=struct.unpack_from('<IIIII',b,at+8);out=[]
    def length(p,w):
        n=int.from_bytes(b[p:p+w],'little');mask=1<<(8*w-1)
        return (((n&~mask)<<(8*w))|int.from_bytes(b[p+w:p+2*w],'little'),p+2*w) if n&mask else (n,p+w)
    for i in range(count):
        p=at+start+struct.unpack_from('<I',b,at+hdr+4*i)[0]
        if flags&256:
            _,p=length(p,1);n,p=length(p,1);text=b[p:p+n].decode('utf-8')
        else:n,p=length(p,2);text=b[p:p+2*n].decode('utf-16le')
        out.append(text)
    return out
def parse(b,wanted):
    typ,hdr,size=struct.unpack_from('<HHI',b);assert typ==2 and size==len(b)
    strings=None;out=[]
    for at,t,h,s in chunks(b,hdr,len(b)):
        if t==1:strings=pool(b,at)
        if t!=0x200:continue
        package=struct.unpack_from('<I',b,at+8)[0]
        types=pool(b,at+struct.unpack_from('<I',b,at+268)[0]);keys=pool(b,at+struct.unpack_from('<I',b,at+276)[0])
        type_offset=struct.unpack_from('<I',b,at+284)[0] if h>=288 else 0
        for ta,tt,th,ts in chunks(b,at+h,at+s):
            if tt!=0x201:continue
            tid,flags,reserved,count,start=struct.unpack_from('<BBHII',b,ta+8)
            assert not flags&~3,('unsupported type flags',flags)
            if flags&1:
                pairs=[struct.unpack_from('<HH',b,ta+th+4*i) for i in range(count)]
                offsets=[(i,off*4) for i,off in pairs]
            elif flags&2:
                offsets=[(i,off*4) for i in range(count) if (off:=struct.unpack_from('<H',b,ta+th+2*i)[0])!=0xffff]
            else:offsets=[(i,off) for i in range(count) if (off:=struct.unpack_from('<I',b,ta+th+4*i)[0])!=0xffffffff]
            for idx,off in offsets:
                rid=(package<<24)|((tid+type_offset)<<16)|idx
                if rid not in wanted:continue
                p=ta+start+off;esz,eflags,key=struct.unpack_from('<HHI',b,p)
                assert esz>=8 and not eflags&9,('unsupported complex/compact entry',hex(rid),eflags)
                vs,vr,vt,data=struct.unpack_from('<HBBI',b,p+esz);assert vs==8
                out.append({'id':f'0x{rid:08x}','type':types[tid-1],'name':keys[key],'type_chunk_offset':ta,
                            'entry_file_offset':p,'type_flags':flags,'entry_flags':eflags,
                            'config_hex':b[ta+20:ta+th].hex(),'value_type':vt,'data':data,
                            'file':strings[data] if vt==3 else None,'raw_entry_value_hex':b[p:p+esz+8].hex()})
    return out
def main():
    ids={s for r in load(PREV/'results/resource_decode_gaps.json')['logs'] for s in r['unique_unresolved_ids']};assert len(ids)==427
    wanted={int(s,16) for s in ids};records=[]
    public=load(PREV/'results/resource_ids.json.gz')['resources']
    for apk in sorted((SOURCE/'apk').glob('*.apk')):
        with zipfile.ZipFile(apk) as z:
            if 'resources.arsc' not in z.namelist():continue
            table=z.read('resources.arsc')
            for r in parse(table,wanted):
                if not r['file']:continue
                content=z.read(r['file']);assert len(content)>0
                match=[p for p in public if p['split']==apk.stem and p['id']==r['id']]
                assert len(match)==1 and match[0]['type']==r['type'] and match[0]['name']==r['name']
                records.append({**r,'apk':apk.name,'arsc_sha256':sha(table),'member_size':len(content),'member_sha256':sha(content),'ZIP_CRC_checked':True})
    recovered={r['id'] for r in records};assert recovered==ids
    references=[];binary_xml=[]
    for p in (ROOT/'.research-local/full_reverse/apktool').rglob('*.xml'):
        try:text=p.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            binary_xml.append({'file':p.relative_to(ROOT/'.research-local/full_reverse/apktool').as_posix(),**identity(p)})
            continue
        hits=sorted(s for s in ids if s[2:] in text.lower() or s in text.lower())
        if hits:references.append({'file':p.relative_to(ROOT/'.research-local/full_reverse/apktool').as_posix(),'ids':hits})
    save(RESULTS/'resource_resolution.json',{'prior_warning_events':692,'prior_distinct_ids':427,'raw_ARSC_resolved_ids':len(recovered),
         'types':dict(collections.Counter(r['type'] for r in records)),'entries':records,'decoded_XML_references':references,'non_text_XML_not_searched':binary_xml,
         'verified':'Exact ID -> raw ARSC entry -> density-specific ZIP member/hash/CRC, cross-checked against Apktool public.xml.',
         'limits':'All 427 gaps are drawable file values in xxhdpi split. This resolves these IDs, not full UI semantics or all Android configuration selection; original decode warnings/logs retained. No APK rebuilding.'})
    print('PASS:',len(recovered),'IDs resolved from raw ARSC to',len(records),'original ZIP files;',len(references),'decoded XML references')
if __name__=='__main__':main()
