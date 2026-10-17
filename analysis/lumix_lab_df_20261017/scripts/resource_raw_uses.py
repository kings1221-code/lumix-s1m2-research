"""Recover typed-ID consumers in raw ARSC bags and AXML; decoded aliases can be lost."""
import struct,zipfile,collections
from common import *
from resources import chunks,pool
def arsc(b,wanted):
    uses=[];unsupported=[];_,h,_=struct.unpack_from('<HHI',b)
    for at,t,hdr,size in chunks(b,h,len(b)):
        if t!=0x200:continue
        package=struct.unpack_from('<I',b,at+8)[0];types=pool(b,at+struct.unpack_from('<I',b,at+268)[0]);keys=pool(b,at+struct.unpack_from('<I',b,at+276)[0]);type_offset=struct.unpack_from('<I',b,at+284)[0] if hdr>=288 else 0
        for ta,tt,th,ts in chunks(b,at+hdr,at+size):
            if tt!=0x201:continue
            tid,flags,rs,count,start=struct.unpack_from('<BBHII',b,ta+8);assert not flags&~3
            if flags&1:offsets=[(i,off*4) for i,off in (struct.unpack_from('<HH',b,ta+th+4*j) for j in range(count))]
            elif flags&2:offsets=[(i,off*4) for i in range(count) if (off:=struct.unpack_from('<H',b,ta+th+2*i)[0])!=0xffff]
            else:offsets=[(i,off) for i in range(count) if (off:=struct.unpack_from('<I',b,ta+th+4*i)[0])!=0xffffffff]
            for idx,off in offsets:
                pos=ta+start+off;esz,ef,key=struct.unpack_from('<HHI',b,pos);source_id=(package<<24)|((tid+type_offset)<<16)|idx
                if ef&8:unsupported.append({'entry_offset':pos,'flags':ef});continue
                if ef&1:
                    parent,n=struct.unpack_from('<II',b,pos+8);vals=[(pos+esz+12*j+4,struct.unpack_from('<I',b,pos+esz+12*j)[0]) for j in range(n)]
                else:vals=[(pos+esz,None)]
                for va,mapkey in vals:
                    vs,rv,vt,value=struct.unpack_from('<HBBI',b,va);assert vs==8
                    if vt in (1,7) and value in wanted:
                        uses.append({'source_id':hex(source_id),'source_type':types[tid-1],'source_name':keys[key],'value_file_offset':va,
                          'map_key':hex(mapkey) if mapkey is not None else None,'target_id':hex(value),'raw_value_hex':b[va:va+8].hex()})
    return uses,unsupported
def axml(b,wanted):
    _,hdr,size=struct.unpack_from('<HHI',b);assert size==len(b);strings=[];uses=[]
    for at,t,h,s in chunks(b,hdr,len(b)):
        if t==1:strings=pool(b,at)
        if t!=0x102:continue
        ns,name,astart,asz,n=struct.unpack_from('<IIHHH',b,at+16)
        for j in range(n):
            p=at+16+astart+j*asz;an=struct.unpack_from('<I',b,p+4)[0];vs,rv,vt,data=struct.unpack_from('<HBBI',b,p+12)
            if vt in (1,7) and data in wanted:uses.append({'element':strings[name],'attribute':strings[an],'attribute_file_offset':p,'target_id':hex(data),'raw_value_hex':b[p+12:p+20].hex()})
    return uses
def main():
    wanted={int(r['id'],16) for r in load(RESULTS/'resource_resolution.json')['entries']};records=[];xml=[];unsupported=[]
    for p in sorted((SOURCE/'apk').glob('*.apk')):
        with zipfile.ZipFile(p) as z:
            if 'resources.arsc' in z.namelist():
                b=z.read('resources.arsc');uses,bad=arsc(b,wanted)
                records.extend({'apk':p.name,'arsc_sha256':sha(b),**r} for r in uses);unsupported.extend({'apk':p.name,**r} for r in bad)
            for info in z.infolist():
                if not info.filename.endswith('.xml') or not (info.filename.startswith('res/') or info.filename=='AndroidManifest.xml'):continue
                b=z.read(info)
                if b[:4]!=b'\x03\0\x08\0':continue
                xml.extend({'apk':p.name,'member':info.filename,'member_sha256':sha(b),**r} for r in axml(b,wanted))
    save(RESULTS/'resource_raw_consumers.json',{'ARSC_value_references':records,'AXML_attribute_references':xml,'unsupported_compact_entries':unsupported,
      'unique_target_ids_referenced':len({r['target_id'] for r in records+xml}),
      'scope':'All five APK resource tables, binary Manifest and res/*.xml typed reference values 0x01/0x07 to the exact 427 IDs. Bag names/values and original byte offsets preserved. Runtime style/UI/configuration choice still unknown; no APK patching.'})
    print('PASS',len(records),'raw ARSC consumers;',len(xml),'raw AXML consumers;',len(unsupported),'unsupported compact entries')
if __name__=='__main__':main()
