"""Independent raw-Dex / ELF instruction / AXML checks for ABC findings."""
import importlib.util
import struct
import zlib
import zipfile
import xml.etree.ElementTree as ET
from elftools.elf.elffile import ELFFile
from common import *

def axml_names(b):
    assert struct.unpack_from('<HHI',b)==(3,8,len(b))
    pool=[];elements=[];at=8
    def v8(pos):
        n=b[pos];return (((n&127)<<8)|b[pos+1],pos+2) if n&128 else (n,pos+1)
    def v16(pos):
        n=struct.unpack_from('<H',b,pos)[0]
        return (((n&32767)<<16)|struct.unpack_from('<H',b,pos+2)[0],pos+4) if n&32768 else (n,pos+2)
    while at<len(b):
        typ,hdr,size=struct.unpack_from('<HHI',b,at);assert hdr>=8 and size>=hdr and at+size<=len(b)
        if typ==1:
            count,styles,flags,start,style=struct.unpack_from('<IIIII',b,at+8)
            for i in range(count):
                pos=at+start+struct.unpack_from('<I',b,at+hdr+4*i)[0]
                if flags&256:
                    _,pos=v8(pos);n,pos=v8(pos);s=b[pos:pos+n].decode('utf-8')
                else:n,pos=v16(pos);s=b[pos:pos+2*n].decode('utf-16le')
                pool.append(s)
        elif typ==0x102:
            ns,name,attrstart,attrsize,count=struct.unpack_from('<IIHHH',b,at+16)
            selected={}
            for j in range(count):
                aa=at+16+attrstart+j*attrsize
                ans,an,raw=struct.unpack_from('<III',b,aa)
                value_type=b[aa+15];value=struct.unpack_from('<I',b,aa+16)[0]
                key=pool[an]
                if key in ('name','versionCode','versionName','minSdkVersion','targetSdkVersion'):
                    selected[key]={'type':value_type,'value':pool[value] if value_type==3 else value}
            elements.append({'element':pool[name],'chunk_offset':at,'attribute_count':count,'selected_attributes':selected})
        at+=size
    assert at==len(b)
    return elements

def main():
    # Binary XML node names checked against independently decoded XML, for every split.
    manifests=[]
    for apk in (SOURCE/'apk').glob('*.apk'):
        with zipfile.ZipFile(apk) as z:b=z.read('AndroidManifest.xml')
        names=axml_names(b);decoded=WORK/'apktool'/apk.stem/'AndroidManifest.xml'
        expected=[e.tag for e in ET.parse(decoded).iter()]
        # Apktool deliberately moves uses-sdk into apktool.yml; preserve the raw node.
        adjusted=[e['element'] for e in names if e['element']!='uses-sdk']
        assert adjusted==[n for n in expected if n!='uses-sdk'],apk.name
        if apk.name=='com.panasonic.jp.lumixlab-22.apk':
            sdk=next(e for e in names if e['element']=='uses-sdk')['selected_attributes']
            assert sdk['minSdkVersion']['value']==30 and sdk['targetSdkVersion']['value']==35
        manifests.append({'apk':apk.name,'raw_manifest_sha256':sha(b),'elements':names,
                          'node_sequence_matches_apktool_except_uses_sdk_moved_to_yaml':True})
    save(RESULTS/'manifest_binary_check.json',{'manifests':manifests,
        'limits':'Independent string-pool/chunk/node-sequence and raw SDK/version attribute check. Apktool removes uses-sdk into YAML. Not full resource-reference/attribute semantic validation.'})
    # Original DEX locations independently derived, no Java as original-source assumption.
    spec=importlib.util.spec_from_file_location('offsets',ROOT/'analysis/lab_stage1_20261015/dex_offsets.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    off={n:mod.offsets(SOURCE/'extracted/base'/n) for n in ('classes.dex','classes2.dex')}
    raw={n:(SOURCE/'extracted/base'/n).read_bytes() for n in off}
    sem=jsonl(WORK/'semantic_instructions.jsonl');evidence=[]
    for r in sem:
        loc=off[r['dex']][r['method']];assert r['code_units']==loc['code_units']
        assert sum(i['width_cu'] for i in r['instructions'])==r['code_units']
        small=[]
        if r['method'].startswith(('Ll0/h;->D(','Ll0/h;->L(','Ll0/h;->M(','Lcom/google/android/gms/tasks/NativeOnCompleteListener;->onComplete')):
            for i in r['instructions']:
                if i['opcode'].startswith('invoke-') or 'target_cu' in i or i.get('literal') in (0x49484452,0x65584966,0x69545874):
                    at=loc['insns_offset']+2*i['offset_cu']
                    small.append({**i,'file_offset':at,'raw_hex':raw[r['dex']][at:at+2*i['width_cu']].hex()})
        method_bytes=raw[r['dex']][loc['insns_offset']:loc['insns_offset']+2*loc['code_units']] if loc['insns_offset'] is not None else b''
        evidence.append({'method':r['method'],'dex':r['dex'],'location':loc,'calls':r['calls'],
                         'instruction_sha256':sha(method_bytes),
                         'selected_instructions':small})
    save(RESULTS/'semantic_dex_evidence.json',{'methods':evidence,'method_count':len(sem),
         'smali_files':[{'path':p.relative_to(WORK/'smali').as_posix(),**file_id(p)} for p in (WORK/'smali').rglob('*.smali')],
         'limits':'Selected Baksmali source remains local; not complete high-level Java recovery.'})
    native=[];checked=0
    paths=[WORK/'native_results/libllc.so.json',WORK/'native_results_refined/libcube_merge.so.json']
    for path in paths:
        x=load(path);library=x['library'];inputpath=SOURCE/'extracted/arm64/lib/arm64-v8a'/library
        with inputpath.open('rb') as f:
            elf=ELFFile(f);blob=inputpath.read_bytes();funcs=[]
            for fn in x['functions']:
                for ins in fn['instructions']:
                    va=int(ins['address'],16)-x['image_base'];data=bytes.fromhex(ins['bytes'])
                    seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+len(data)<=s['p_vaddr']+s['p_filesz'])
                    pos=seg['p_offset']+va-seg['p_vaddr'];assert blob[pos:pos+len(data)]==data;checked+=1
                funcs.append({k:v for k,v in fn.items() if k not in ('c','instructions')})
            native.append({'library':library,**file_id(inputpath),'image_base':x['image_base'],
                           'identified_project_functions':x['identified_project_functions'],'selected_functions':funcs})
    cube=load(paths[1]);seed=next(f for f in cube['functions'] if f['elf_va']=='0x51d0');ins={int(i['address'],16):i for i in seed['instructions']}
    assert 'x2,sp,#0x38' in ins[0x105260]['instruction'] and '00104e60' in ins[0x105268]['instruction']
    critical=[i for i in seed['instructions'] if 0x105258<=int(i['address'],16)<=0x105274]
    save(RESULTS/'native_evidence.json',{'libraries':native,'instruction_rows_original_ELF_checked':checked,
         'cube_merge_third_argument_instructions':critical,
         'correction':'Ghidra caller C omitted the third argument at cube_merge_files -> 0x4e60. Raw ARM64 sets x2=sp+0x38, then passes that output structure to writer.',
         'limits':'C prototypes remain tentative. Full C/instruction listings stay local; selected caller/callee graph is analysis-derived.'})
    # Synthetic independent control for the observed PNG iTXt CRC consumer.
    prefix=b'XML:com.adobe.xmp\0\0\0\0\0';payload=b'<x>synthetic</x>';assert len(prefix)==22
    crc=zlib.crc32(b'iTXt'+prefix+payload)&0xffffffff
    chain=zlib.crc32(b'iTXt');chain=zlib.crc32(prefix,chain);chain=zlib.crc32(payload,chain)&0xffffffff
    assert chain==crc
    save(RESULTS/'verification.json',{'status':'PASS','manifest_node_sequences':len(manifests),'semantic_methods_raw_offsets_checked':len(sem),
         'native_instruction_rows_bytes_checked':checked,'png_itxt_synthetic_control':{'prefix_length':22,'payload_length':len(payload),'chunk_crc32':f'{crc:08x}','incremental_equals_joined':True},
         'target_program_executed':False,'camera_io':False,
         'scope':'Local structural/byte/CRC controls; no App execution or complete semantic proof.'})
    print('PASS:',len(manifests),'binary manifests;',len(sem),'DEX method offsets;',checked,'ARM64 instruction bytes; PNG CRC control')
if __name__=='__main__':main()
