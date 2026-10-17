"""Resolve AArch64 PLT/GOT + real direct BL sites to selected imported APIs.
Linear branch-word inventory is not CFG recovery or function semantic coverage.
"""
import collections,struct,re
from elftools.elf.elffile import ELFFile
from common import *
INTEREST=re.compile(r'^(?:SSL_|TLS_|EVP_|HMAC|SHA[0-9]*_|MD5_|AES_|RSA_|EC_|ECDH_|ECDSA_|X509_|BIO_|CRYPTO_|OPENSSL_|PEM_|inflate|deflate|crc32|adler32|compress|uncompress|dlopen$|dlsym$)')
def main():
    libs=[]
    for meta in load(PREV/'results/elf_structure.json.gz')['libraries']:
        path=SOURCE/'extracted/arm64/lib/arm64-v8a'/meta['library'];assert identity(path)=={k:meta[k] for k in ('size','sha256')}
        with path.open('rb') as f:
            elf=ELFFile(f);dyn=elf.get_section_by_name('.dynsym');plt=elf.get_section_by_name('.plt');imports={};relocs=[]
            for sec in elf.iter_sections():
                if sec['sh_type']=='SHT_RELA':
                    syms=elf.get_section(sec['sh_link'])
                    for r in sec.iter_relocations():
                        if r['r_info_type']==1026:
                            sym=syms.get_symbol(r['r_info_sym']);relocs.append((r['r_offset'],sym.name))
            got=dict(relocs);plt_rows=[]
            if plt:
                b=plt.data()
                for offset in range(0,len(b)-15,16):
                    a=plt['sh_addr']+offset;w,l=struct.unpack_from('<II',b,offset)
                    if w&0x9f00001f!=0x90000010 or l&0xffc003ff!=0xf9400211:continue
                    imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2)
                    if imm&0x100000:imm-=0x200000
                    slot=(a&~4095)+(imm<<12)+(((l>>10)&0xfff)*8)
                    if slot in got:
                        name=got[slot]
                        if INTEREST.match(name):imports[a]=name;plt_rows.append({'plt_va':hex(a),'GOT_va':hex(slot),'symbol':name,'raw_hex':b[offset:offset+16].hex()})
            calls=[];ranges=[];dynfuncs=[]
            for s in dyn.iter_symbols():
                if s['st_info']['type']=='STT_FUNC' and s['st_shndx']!='SHN_UNDEF' and s['st_size']:
                    dynfuncs.append((s['st_value'],s['st_value']+s['st_size'],s.name))
            if imports:
                for sec in elf.iter_sections():
                    if sec['sh_flags']&4 and sec['sh_type']=='SHT_PROGBITS':
                        b=sec.data();assert sec['sh_addr']%4==0 and len(b)%4==0
                        ranges.append({'section':sec.name,'va':hex(sec['sh_addr']),'offset':sec['sh_offset'],'bytes':len(b),'sha256':sha(b)})
                        for off in range(0,len(b),4):
                            w=struct.unpack_from('<I',b,off)[0]
                            if w&0xfc000000!=0x94000000:continue
                            imm=w&0x3ffffff
                            if imm&0x2000000:imm-=0x4000000
                            at=sec['sh_addr']+off;target=at+4*imm
                            if target in imports:
                                names=[name for lo,hi,name in dynfuncs if lo<=at<hi]
                                calls.append({'elf_va':hex(at),'file_offset':sec['sh_offset']+off,'raw_hex':b[off:off+4].hex(),'target_PLT_va':hex(target),
                                              'symbol':imports[target],'containing_dynsym_functions':names})
            libs.append({'library':meta['library'],'sha256':meta['sha256'],'selected_PLT_entries':plt_rows,'direct_BL_calls':calls,'linear_scan_ranges':ranges,
                         'JUMP_SLOT_total':len(relocs),'limits':'Direct BL to verified conventional PLT only. Indirect calls/dlsym results/static linked algorithms not resolved; dynsym range name is not complete function discovery.'})
            print(meta['library'],len(plt_rows),'selected PLT',len(calls),'BL sites',flush=True)
    save(RESULTS/'native_import_calls.json.gz',{'pattern':INTEREST.pattern,'libraries':libs,'method':'Actual RELA JUMP_SLOT -> ADRP/LDR GOT -> AArch64 BL immediate. Every reported instruction is from hashed original ELF. Metadata is not proof that a firmware input reaches these calls.'},True)
if __name__=='__main__':main()
