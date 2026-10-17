"""JNI bounded gap audit, per-library evidence levels, failed-method/E-G preparation."""
import collections,re
from elftools.elf.elffile import ELFFile
from common import *
def main():
    ms=methods();by={m['method']:m for m in ms};prior=load(PREV/'results/jni_unresolved_update.json')['entries'];libs=load(PREV/'results/elf_structure.json.gz')['libraries']
    inputs=load(PREV/'results/input_manifest.json')
    for r in inputs['inputs']:
        p=Path(r['path_token'].replace('<SOURCE_ROOT>',str(SOURCE))) if r['kind']=='APK' else SOURCE/'extracted/base'/r['member'] if r['kind']=='DEX' else SOURCE/'extracted/arm64'/r['member']
        assert identity(p)=={k:r[k] for k in ('size','sha256')}
    save(RESULTS/'input_manifest.json',inputs)
    sonames={};symchecks=[]
    for l in libs:
        p=SOURCE/'extracted/arm64/lib/arm64-v8a'/l['library']
        with p.open('rb') as f:
            elf=ELFFile(f);dyn=elf.get_section_by_name('.dynamic');names=[t.soname for t in dyn.iter_tags() if t.entry.d_tag=='DT_SONAME'];sonames[l['library']]=names
            related=[s for s in l['symbols'] if 'splitYuvArrayToYAndUv' in s['name'] or 'NativeOnCompleteListener' in s['name'] or 'nativeOnComplete' in s['name']]
            rel=[]
            for sec in elf.iter_sections():
                if sec['sh_type'] in ('SHT_RELA','SHT_REL'):
                    syms=elf.get_section(sec['sh_link'])
                    for r in sec.iter_relocations():
                        if r['r_info_sym']:
                            name=syms.get_symbol(r['r_info_sym']).name
                            if any(q in name for q in ('splitYuvArrayToYAndUv','NativeOnCompleteListener','nativeOnComplete')):rel.append({'offset':r['r_offset'],'type':r['r_info_type'],'symbol':name})
            symchecks.append({'library':l['library'],'sha256':l['sha256'],'related_dynsym':related,'related_symbol_relocations':rel})
    callers={}
    for target in [r['java_method'] for r in prior]+['Lcom/google/android/gms/tasks/NativeOnCompleteListener;->createAndAddCallback(Lcom/google/android/gms/tasks/Task;J)V']:
        callers[target]=[{'caller':m['method'],'dex':m['dex'],'cu':c['offset_cu']} for m in ms for c in m['calls'] if c['reference']==target]
    save(RESULTS/'jni_gap_audit.json',{'still_unresolved':prior,'exact_direct_callers':callers,'ELF_symbol_relocation_checks':symchecks,'SONAME_by_file':sonames,
         'new_case_specific_chain':{'caller':'Lh5/l;->b()V','shared_callable':'Lg5/k;->call()Ljava/lang/Object;','selector':2,
           'java_native':'Lcom/panasonic/jp/lumixlab/LlcApplication;->writeVideoRatingJni(Ljava/lang/String;I)I','library':'libllc.so','ELF_va':'0x160c8',
           'native_consumer':'writeVideoRating(path_utf8, rating_int)','buffer_boundary':'JNIEnv +0x548 GetStringUTFChars; +0x550 ReleaseStringUTFChars; integer return preserved',
           'basis':'r8_callable_cases.json plus inherited exact-input Ghidra wrapper and original instructions; downstream writer semantics not newly recovered'},
         'negative_scope':'All 18 exact-input dynsym and their symbol-based relocations, original 214 JNI map, all 76901 DEX methods explicit invokes, and recovered literal targets in the 243 dynamic sites. Absence here excludes neither computed/external registration nor remote Google native modules. No runtime binding test.'})
    unique=collections.defaultdict(set)
    for p in (ROOT/'.research-local/stage1/ghidra_results').glob('*.json'):
        x=load(p)
        for f in x['functions']:unique[x['program']].add(f['elf_va'])
    old=load(PREV/'results/native_evidence.json')
    for l in old['libraries']:
        for f in l['selected_functions']:unique[l['library']].add(f['elf_va'])
    cfg=collections.defaultdict(list)
    for p in (WORK/'native').glob('*.json'):
        x=load(p)
        for f in x['functions']:unique[x['library']].add(f['elf_va']);cfg[x['library']].append({'elf_va':f['elf_va'],'blocks':len(f['blocks']),'decompile_completed':f['decompile_completed']})
    cover=[]
    for l in libs:
        cover.append({'library':l['library'],'sha256':l['sha256'],'symbol_inventory':{'dynsym_entries':len(l['symbols']),'complete_for_section':True},
          'selected_disassembly_functions':sorted(unique[l['library']],key=lambda x:int(x,16)),'explicit_tool_CFG_exports':cfg[l['library']],
          'bounded_synthetic_semantic_controls':(['0x5714: finite tetrahedral model','0x4e60: composition model','0x4fdc: textual output control'] if l['library']=='libcube_merge.so' else []),
          'fully_semantically_validated_functions':0,'limit':'Symbol entries, selected disassembly, tool CFG and bounded semantic models have different denominators; no whole-library percentage.'})
    save(RESULTS/'native_coverage.json',{'libraries':cover,'unique_selected_functions':sum(len(s) for s in unique.values()),'new_CFG_functions':sum(len(s) for s in cfg.values()),'full_semantics_claimed':False})
    failed=load(PREV/'results/failed_method_progress.json')['methods'];rank=[];nativeset={x['method'] for x in ms if x['native']}
    for f in failed:
        if f['method'].startswith('Ll0/h;->D('):continue
        m=by[f['method']];refs=[c['reference'] for c in m['calls']];flags=[];score=0
        for label,n,ps in [('file_IO',6,('Ljava/io/','Landroid/content/ContentResolver;','Landroid/os/ParcelFileDescriptor;')),
                           ('security_transform',7,('Ljava/security/','Ljavax/crypto/','Ljava/util/zip/')),
                           ('network_BLE',5,('Ljava/net/','Landroid/bluetooth/','Lh6/a;')),
                           ('reflection',4,('Ljava/lang/reflect/','Ljava/lang/Class;->forName'))]:
            matched=[r for r in refs if r.startswith(ps)]
            if matched:score+=n;flags.append({'category':label,'references':sorted(set(matched))})
        natives=[r for r in refs if r in nativeset]
        if natives:score+=8;flags.append({'category':'JNI','references':sorted(set(natives))})
        if f['method'].startswith('Lcom/panasonic/'):score+=5
        if 'MainActivity;' in f['method'] or 'RemoteShootingActivity;' in f['method']:score+=3
        if 'BufferedReader' in f['method']:score+=4
        rank.append({**f,'review_priority_score':score,'direct_evidence_categories':flags,'cost_code_units':m['code_units'],
                     'status':'Structural CFG retained; high-level semantics still pending. Score is triage, not a security severity or restored-code count.'})
    rank.sort(key=lambda r:(-r['review_priority_score'],r['cost_code_units']));assert len(rank)==23
    save(RESULTS/'failed_method_ranking.json',{'criteria':'file6/security7/network5/reflection4/JNI8/Panasonic5/main-or-remote3/BufferedReader4; exact direct references; CU is review cost','methods':rank})
    patterns={'BLE':('Landroid/bluetooth/','Lcom/panasonic/jp/lumixlab/LLCBleCentral;'),
      'WiFi_network':('Landroid/net/wifi/','Landroid/net/ConnectivityManager;','Landroid/net/NetworkSpecifier;','Landroid/net/NetworkRequest'),
      'HTTP_TLS':('Ljavax/net/ssl/','Lh6/a;','Lg8/'),
      'LUT_native':('Lcom/panasonic/jp/lumixlab/LlcApplication;->mergeCubeFiles','Lcom/panasonic/jp/lumixlab/LlcApplication;->readLut')}
    entries=[{'caller':m['method'],'dex':m['dex'],'cu':c['offset_cu'],'target':c['reference'],'groups':[k for k,ps in patterns.items() if c['reference'].startswith(ps)]}
             for m in ms for c in m['calls'] if any(c['reference'].startswith(ps) for ps in patterns.values())]
    api=[{'method':m['method'],'annotations':m['annotations']} for m in ms if m['method'].startswith('Lh6/a;')]
    save(RESULTS/'eg_preparation.json.gz',{'patterns':patterns,'explicit_sites':entries,'client_API_declarations':api,'module_entries_basis':'../lumix_lab_full_reverse/results/module_entries.json.gz',
      'synthetic_candidates':['cube finite-cell math/output','filename SHA256 truncation','Lottie cache-name MD5 branch','Basic header with invented credentials only','gzip/ZIP/JSON roundtrip','firmware short-read control inherited'],
      'limits':'Entry/reference inventory and test planning only. No camera/service I/O, full communication state machine, or full E/G execution.'},True)
    print('PASS 25 inputs; 2 JNI gaps retained;',sum(len(s) for s in unique.values()),'selected native functions;',sum(len(s) for s in cfg.values()),'explicit CFGs; 23 methods ranked;',len(entries),'E/G sites')
if __name__=='__main__':main()
