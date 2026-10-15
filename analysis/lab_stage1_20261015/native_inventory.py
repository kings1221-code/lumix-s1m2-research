"""Inventory ELF exports and candidate JNI registration triples; no library loading."""
import argparse,hashlib,json,re,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

def inspect(path):
 b=path.read_bytes()
 with path.open('rb') as stream:
  elf=ELFFile(stream); loads=[(s['p_vaddr'],s['p_offset'],s['p_filesz'],s['p_flags']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
  def offset(va):
   for v,o,n,f in loads:
    if v<=va<v+n:return o+va-v
  def string(va):
   o=offset(va)
   if o is None:return None
   end=b.find(b'\0',o,min(o+1024,len(b)))
   if end<0:return None
   try:return b[o:end].decode('ascii')
   except UnicodeDecodeError:return None
  symbols=[]; needed=[];relocations={}
  dyn=elf.get_section_by_name('.dynsym')
  if dyn:
   for s in dyn.iter_symbols():
    if s.name:symbols.append({'name':s.name,'va':hex(s['st_value']),'size':s['st_size'],'defined':s['st_shndx']!='SHN_UNDEF','type':s['st_info']['type']})
  for section in elf.iter_sections():
   if section['sh_type']=='SHT_DYNAMIC':
    needed.extend(t.needed for t in section.iter_tags() if t.entry.d_tag=='DT_NEEDED')
   if section['sh_type']=='SHT_RELA':
    symtab=elf.get_section(section['sh_link'])
    for r in section.iter_relocations():
     val=r['r_addend']
     if r['r_info_sym']:val+=symtab.get_symbol(r['r_info_sym'])['st_value']
     relocations[r['r_offset']]=val
  def ptr(va):
   if va in relocations:return relocations[va]
   o=offset(va)
   return struct.unpack_from('<Q',b,o)[0] if o is not None and o+8<=len(b) else 0
  def executable(va):return any(v<=va<v+n and f&1 for v,o,n,f in loads)
  tables=[]
  for section in elf.iter_sections():
   if section.name not in ('.data.rel.ro','.data','.rodata'):continue
   for va in range(section['sh_addr'],section['sh_addr']+section['sh_size']-23,8):
    n=string(ptr(va))
    if not n or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$<>]*',n):continue
    sig=string(ptr(va+8))
    if not sig or not re.fullmatch(r'\([\[BCDFIJSZL;/A-Za-z0-9_$]*\)[\[VBCDFIJSZL;/A-Za-z0-9_$]+',sig):continue
    target=ptr(va+16)
    if executable(target):tables.append({'table_va':hex(va),'name':n,'signature':sig,'function_va':hex(target),'status':'candidate_triple_requires_registration_consumer'})
 return {'library':path.name,'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'elf_machine':elf['e_machine'],'needed':needed,
         'jni_onload':[s for s in symbols if s['defined'] and s['name']=='JNI_OnLoad'],
         'static_jni_exports':[s for s in symbols if s['defined'] and s['name'].startswith('Java_')],
         'dynamic_jni_candidates':tables,'symbols':symbols}

def main():
 p=argparse.ArgumentParser();p.add_argument('--libraries',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 assert not a.output.exists()
 rows=[inspect(x) for x in sorted(a.libraries.glob('*.so'))]
 a.output.write_text(json.dumps({'method':'ELF dynsym, DT_NEEDED, RELA-aware aligned JNINativeMethod triple enumeration; no target execution','libraries':rows},indent=2)+'\n',encoding='utf-8',newline='\n')
 print(json.dumps([{'lib':r['library'],'onload':r['jni_onload'],'static':len(r['static_jni_exports']),'dynamic_triples':len(r['dynamic_jni_candidates'])} for r in rows]))
if __name__=='__main__':main()
