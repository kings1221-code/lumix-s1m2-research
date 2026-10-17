"""Narrow original-byte/relocation audit of the two unresolved names, no key search."""
import struct
from elftools.elf.elffile import ELFFile
from common import *
NAMES=('splitYuvArrayToYAndUv','nativeOnComplete','com/google/android/gms/tasks/NativeOnCompleteListener')
def hits(b,needle):
    out=[];at=0
    while (pos:=b.find(needle,at))>=0:out.append(pos);at=pos+1
    return out
def main():
    libs=[]
    for p in sorted((SOURCE/'extracted/arm64/lib/arm64-v8a').glob('*.so')):
        b=p.read_bytes();names={s:hits(b,s.encode()+b'\0') for s in NAMES};rel=[];pointers=[];ranges=[]
        with p.open('rb') as f:
            e=ELFFile(f)
            for sec in e.iter_sections():
                if p.name=='libllc.so' and sec['sh_type']=='SHT_RELA':
                    rel.extend({'section':sec.name,'offset':r['r_offset'],'type':r['r_info_type'],'addend':r['r_addend']} for r in sec.iter_relocations() if r['r_addend']==0x16e18)
                if p.name=='libllc.so' and sec['sh_type']=='SHT_PROGBITS' and sec['sh_flags']&2 and not sec['sh_flags']&4:
                    data=sec.data();ranges.append({'section':sec.name,'file_offset':sec['sh_offset'],'size':len(data),'sha256':sha(data)})
                    pointers.extend({'section':sec.name,'file_offset':sec['sh_offset']+a,'ELF_va':sec['sh_addr']+a} for a in hits(data,struct.pack('<Q',0x16e18)))
        libs.append({'library':p.name,**identity(p),'exact_NUL_terminated_name_hits':names,'split_function_exact_RELA_addends':rel,'split_function_stored_uint64_hits':pointers,'stored_pointer_scan_ranges':ranges})
    save(RESULTS/'jni_registration_extension.json',{'libraries':libs,'patterns':{'strings':[n+'\\0' for n in NAMES],'split_pointer_uint64_le':hex(0x16e18)},
      'limits':'Exact NUL-terminated bytes (not proof of a JNI table), libllc all RELA exact-addend matches, and allocated non-executable PROGBITS exact uint64 values. No search of runtime-created strings/pointers, computed registration, system libraries or external Google modules. Results do not establish runtime binding or nonexistence.'})
    print('JNI narrow audit:',sum(len(v) for l in libs for v in l['exact_NUL_terminated_name_hits'].values()),'NUL-name hits;',sum(len(l['split_function_exact_RELA_addends']) for l in libs),'exact RELA;',sum(len(l['split_function_stored_uint64_hits']) for l in libs),'stored pointers')
if __name__=='__main__':main()
