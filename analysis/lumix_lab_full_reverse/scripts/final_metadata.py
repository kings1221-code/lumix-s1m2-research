"""Bounded coverage, resource warnings and Smali cross-checks; no new scans."""
import collections
import gzip
import re
from elftools.elf.elffile import ELFFile
from common import *
def main():
    warnings=[]
    for p in WORK.glob('*.apktool.log'):
        lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
        ids=[m.group(1) for s in lines if (m:=re.search(r'Unresolved resource reference:.*?, id=(0x[0-9a-f]+), type=',s))]
        warnings.append({'apk':p.name.removesuffix('.apktool.log'),'warning_lines':sum(s.startswith('W:') for s in lines),
                         'unresolved_reference_events':len(ids),'unique_unresolved_ids':sorted(set(ids)),'local_log_id':file_id(p)})
    save(RESULTS/'resource_decode_gaps.json',{'logs':warnings,
        'limits':'Separate split decoding has unresolved references; whole-container hashing is complete, full merged resource semantics are not. Cause not independently proven.'})
    sem=jsonl(WORK/'semantic_instructions.jsonl');smali=[]
    for desc,path,name in [('Ll0/h;->D(Ljava/io/BufferedInputStream;Ljava/io/BufferedOutputStream;)V',WORK/'smali/l0/h.smali','D(Ljava/io/BufferedInputStream;Ljava/io/BufferedOutputStream;)V'),
                           ('Lcom/google/android/gms/tasks/NativeOnCompleteListener;->onComplete(Lcom/google/android/gms/tasks/Task;)V',WORK/'smali/com/google/android/gms/tasks/NativeOnCompleteListener.smali','onComplete(Lcom/google/android/gms/tasks/Task;)V')]:
        text=path.read_text(encoding='utf-8');block=next(s for s in text.split('.method ') if s.split('\n',1)[0].endswith(name)).split('.end method')[0]
        lines=block.splitlines()[1:];ops=[];annotation=False
        for line in lines:
            s=line.strip()
            if s.startswith('.annotation'):annotation=True
            if annotation:
                if s.startswith('.end annotation'):annotation=False
                continue
            if s and not s.startswith(('.',':','#')):ops.append(s.split()[0])
        r=next(r for r in sem if r['method']==desc);expected=[i['opcode'] for i in r['instructions']]
        assert ops==expected,(desc,len(ops),len(expected))
        smali.append({'method':desc,'opcode_sequence_match':True,'instruction_count':len(ops),'smali_id':file_id(path)})
    save(RESULTS/'smali_crosscheck.json',{'methods':smali,'basis':'Apktool 3.0.3 Baksmali selected-class output versus JADX 1.5.6 dexlib2 raw instruction sequence; operands/offsets separately retained.'})
    previous=[]
    for p in (ROOT/'.research-local/stage1/ghidra_results').glob('*.json'):
        x=load(p)
        previous.extend((x['program'],f['elf_va']) for f in x['functions'])
    current=load(RESULTS/'native_evidence.json');perlib=collections.Counter(l for l,v in set(previous)|{(r['library'],f['elf_va']) for r in current['libraries'] for f in r['selected_functions']})
    prior=load(ROOT/'.research-local/stage1/elf_inventory.json')['libraries'];native=[]
    for r in prior:
        path=SOURCE/'extracted/arm64/lib/arm64-v8a'/r['library']
        with path.open('rb') as f:
            elf=ELFFile(f);dyn=elf.get_section_by_name('.dynamic')
            init=[{'tag':t.entry.d_tag,'value':t.entry.d_val} for t in dyn.iter_tags() if t.entry.d_tag in ('DT_INIT','DT_INIT_ARRAY','DT_INIT_ARRAYSZ')]
        native.append({'library':r['library'],'sha256':r['sha256'],'dynsym_defined_STT_FUNC':sum(s['defined'] and s['type']=='STT_FUNC' for s in r['symbols']),
                       'selected_ghidra_functions_including_prior':perlib[r['library']],'init_dynamic_tags':init,
                       'semantic_status':'partial selected consumers only' if perlib[r['library']] else 'ELF/symbol/dependency inventory only; function semantics pending'})
    mapping=load(ROOT/'analysis/lab_stage1_20261015/results/jni_mapping_verified.json')
    methods=jsonl(ROOT/'.research-local/stage1/dex_index_v2.jsonl');holes=[]
    for row in mapping['mapping']:
        if row['status'] not in ('static_symbol_correspondence','verified_dynamic_registration_static_path'):
            callers=[{'method':m['method'],'dex':m['dex'],'offset_cu':c['offset_cu']} for m in methods for c in m['calls'] if c['reference']==row['java_method']]
            holes.append({**row,'visible_direct_callers':callers,'binding_status':'still unresolved; additional explicit caller/buffer evidence does not establish runtime binding'})
    save(RESULTS/'jni_unresolved_update.json',{'entries':holes,'negative_scope':'same exact two DEX and 18 ELF; conventional symbol/table/OnLoad evidence retained; computed/external registration not excluded'})
    save(RESULTS/'coverage.json',{'APK_inputs':5,'APK_members_fully_hashed':4867,'DEX_classes':14812,'DEX_fields':48914,'DEX_methods':76901,'explicit_invoke_sites':349415,
         'DEX_strings_ID_hash_only':73540,'resource_ids':13886,'selected_async_sites':680,'reflection_load_candidate_sites':243,
         'new_raw_method_dumps':18,'new_semantically_expanded_failed_methods':1,'failed_method_full_semantics_completed':0,
         'native_libraries':native,'selected_native_functions_unique_including_prior':sum(perlib.values()),
         'native_cumulative_semantics_limit':'Function output/byte checking is not complete semantics; dynsym and Ghidra function denominators are different.',
         'D_E_F_G_status':'not expanded; prior evidence preserved, user review gate after ABC interim report'})
    print('PASS: 2 Baksmali opcode sequences; coverage/resources/JNI unknown states recorded')
if __name__=='__main__':main()
