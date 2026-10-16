"""Supplement ELF metadata absent from prior symbol inventory; no target execution."""
import struct
from elftools.elf.elffile import ELFFile
from common import *
def main():
    prior=load(ROOT/'.research-local/stage1/elf_inventory.json')['libraries']
    out=[];targets=['libllc.so|0x16e18','libllc.so|0x122ac','libcube_merge.so|0x51d0']
    for p in sorted((SOURCE/'extracted/arm64/lib/arm64-v8a').glob('*.so')):
        old=next(r for r in prior if r['library']==p.name)
        assert file_id(p)=={'size':old['size'],'sha256':old['sha256']}
        with p.open('rb') as stream:
            elf=ELFFile(stream);sections=[{'name':s.name,'type':s['sh_type'],'va':s['sh_addr'],'offset':s['sh_offset'],'size':s['sh_size'],'flags':s['sh_flags']} for s in elf.iter_sections()]
            segments=[{'type':s['p_type'],'va':s['p_vaddr'],'offset':s['p_offset'],'filesz':s['p_filesz'],'memsz':s['p_memsz'],'flags':s['p_flags']} for s in elf.iter_segments()]
            init=[];section=elf.get_section_by_name('.init_array')
            if section:
                data=section.data();relocs={}
                for sec in elf.iter_sections():
                    if sec['sh_type']=='SHT_RELA':
                        syms=elf.get_section(sec['sh_link'])
                        for rel in sec.iter_relocations():
                            if section['sh_addr']<=rel['r_offset']<section['sh_addr']+section['sh_size']:
                                relocs[rel['r_offset']]={'type':rel['r_info_type'],'addend':rel['r_addend'],'symbol':syms.get_symbol(rel['r_info_sym']).name if rel['r_info_sym'] else None}
                for i in range(0,len(data),8):
                    at=section['sh_addr']+i;raw=struct.unpack_from('<Q',data,i)[0];rel=relocs.get(at)
                    resolved=rel['addend'] if rel and rel['type']==1027 and rel['symbol'] is None else raw if not rel else None
                    init.append({'slot_va':at,'raw':raw,'relocation':rel,'resolved_ELF_va':resolved})
                    if p.name=='libllc.so' and resolved:targets.append(p.name+'|'+hex(resolved))
            out.append({'library':p.name,**file_id(p),'header':{'machine':elf['e_machine'],'type':elf['e_type'],'entry':elf['e_entry'],'class':elf.elfclass,'little_endian':elf.little_endian},
                        'sections':sections,'segments':segments,'init_array':init,'needed':old['needed'],
                        'symbols':old['symbols'],'symbol_basis':'exact same input and preserved stage1 dynsym; no symbol scan repeated'})
    save(RESULTS/'elf_structure.json.gz',{'libraries':out,'limits':'ELF metadata, dynsym and init-array addresses are not semantic function coverage.'},True)
    with (WORK/'native_targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(targets)+'\n')
    print('PASS: 18 ELF headers/sections/segments/initializers; prior symbol identities matched')
if __name__=='__main__':main()
