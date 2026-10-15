"""Recheck DEX CFGs, key register flows and Ghidra instruction bytes against exact inputs."""
import collections,gzip,hashlib,json,re,sys
from pathlib import Path
from elftools.elf.elffile import ELFFile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from dex_offsets import offsets
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];WORK=ROOT/'.research-local/stage1';OUT=HERE/'results'
SOURCE=Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])
def save(name,data):(OUT/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
selected={m['method']:m for m in map(json.loads,(WORK/'selected_instructions.jsonl').open(encoding='utf-8'))}
raw={d:offsets(SOURCE/'extracted/base'/d) for d in ['classes.dex','classes2.dex']}
def location(m,cu):return hex(raw[m['dex']][m['method']]['insns_offset']+2*cu)
def cfg(m):
 ins=m['instructions'];all_by={i['offset_cu']:i for i in ins};exe=[i for i in ins if not i['opcode'].endswith('payload')];by={i['offset_cu']:i for i in exe}
 assert sum(i['width_cu'] for i in ins)==m['code_units']
 assert all(all_by[a['offset_cu']+a['width_cu']]==b for a,b in zip(ins,ins[1:]))
 assert all(0<=r<m['registers'] for i in ins for r in i['registers'])
 leaders={0};successors={}
 for i in exe:
  cu=i['offset_cu'];op=i['opcode'];nxt=cu+i['width_cu'];succ=[]
  if op.startswith('goto'):succ=[i['target_cu']]
  elif op.startswith('if-'):succ=[i['target_cu'],nxt]
  elif op in ('packed-switch','sparse-switch'):
   succ=[nxt]+[cu+e['relative_target_cu'] for e in all_by[i['target_cu']]['switch_elements']]
  elif not op.startswith(('return','throw')) and nxt in by:succ=[nxt]
  assert all(t in by for t in succ),(m['method'],cu,succ)
  successors[cu]=succ
  if op.startswith(('if-','goto','return','throw')) or op in ('packed-switch','sparse-switch'):
   leaders.update(succ)
   if nxt in by:leaders.add(nxt)
 for t in m['try_blocks']:
  for point in [t['start_cu'],t['start_cu']+t['count_cu']]+[h['target_cu'] for h in t['handlers']]:
   assert point in all_by or point==m['code_units']
   if point in by:leaders.add(point)
 leaders=sorted(leaders);blocks=[]
 for start,end in zip(leaders,leaders[1:]+[m['code_units']]):
  body=[i for i in exe if start<=i['offset_cu']<end]
  if not body:continue
  exceptional=[]
  for index,t in enumerate(m['try_blocks']):
   if any(t['start_cu']<=i['offset_cu']<t['start_cu']+t['count_cu'] for i in body):exceptional.append(index)
  blocks.append({'start_cu':start,'end_cu':end,'normal_successors':successors[body[-1]['offset_cu']],
                 'exception_range_indices_overapprox':exceptional})
 info=raw[m['dex']][m['method']];b=(SOURCE/'extracted/base'/m['dex']).read_bytes()[info['insns_offset']:info['insns_offset']+2*m['code_units']]
 return {'method':m['method'],'dex':m['dex'],'location':info,'instruction_count':len(ins),'instruction_bytes_sha256':hashlib.sha256(b).hexdigest(),
         'block_count':len(blocks),'blocks':blocks,'exception_ranges':m['try_blocks'],'encoded_branch_targets_valid':True,'register_indices_valid':True,
         'status':'structural_control_flow_recovered; semantic_review_is_separate'}
failures=json.loads((OUT/'jadx_failures.json').read_text(encoding='utf-8'))
graphs=[cfg(selected[r['method']]) for r in failures['methods']]
cfg_data={'method':'DEX encoded branch/switch targets and exception ranges; exception edges conservatively overapproximate all protected blocks',
 'error_events':42,'distinct_methods':24,'cfg_verified':len(graphs),'methods':graphs}
cfg_bytes=(json.dumps(cfg_data,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
(WORK/'failed_method_cfg.json').write_bytes(cfg_bytes)
(OUT/'failed_method_cfg.json.gz').write_bytes(gzip.compress(cfg_bytes,mtime=0))
save('failed_method_cfg_index.json',{'uncompressed_sha256':hashlib.sha256(cfg_bytes).hexdigest(),
 'archive':'failed_method_cfg.json.gz','methods':[{k:v for k,v in g.items() if k not in ['blocks','exception_ranges']} for g in graphs]})
ghidra=[];bytecount=0
for p in sorted((WORK/'ghidra_results').glob('*.json')):
 d=json.loads(p.read_text(encoding='utf-8'));path=SOURCE/'extracted/arm64/lib/arm64-v8a'/d['program'];data=path.read_bytes()
 with path.open('rb') as stream:
  elf=ELFFile(stream);segments=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
  for f in d['functions']:
   for i in f['instructions']:
    va=int(i['address'],16)-int(d['image_base'],16);s=next(s for s in segments if s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']);o=s['p_offset']+va-s['p_vaddr'];expected=bytes.fromhex(i['bytes'])
    assert data[o:o+len(expected)]==expected,(d['program'],i['address']);bytecount+=1
   ghidra.append({'library':d['program'],'function':f['name'],'elf_va':f['elf_va'],'ghidra_address':f['entry'],'image_base':d['image_base'],
       'instruction_count':len(f['instructions']),'decompiler_completed':f['decompile_completed'],'instruction_bytes_match_original':True,
       'local_c_sha256':hashlib.sha256(f.get('c','').encode()).hexdigest(),'call_sites':f['calls']})
save('ghidra_verified_functions.json',{'version':'12.1.4','language':'AARCH64:LE:64:v8A','mapping':'Ghidra address = ELF VA + 0x100000; input ELF PT_LOAD origin 0',
 'functions':ghidra,'function_count':len(ghidra),'instruction_byte_comparisons':bytecount,'mismatches':0,
 'limitations':'Ghidra auto-analysis emitted invalid-target warnings outside checked instruction bytes; generated C types and prototypes remain hypotheses. Local full C and project are not published.'})
ff=json.loads((WORK/'ghidra_results/libffmpeg_mediametadataretriever_jni.so.json').read_text(encoding='utf-8'))
helper=next(f for f in ff['functions'] if f['elf_va']=='0x7428');reg=next(f for f in ff['functions'] if f['elf_va']=='0x748c')
assert 'wseemann/media/FFmpegMediaMetadataRetriever' in helper['c'] and '0xf' in helper['c'] and '00115b50' in helper['c'] and '0x6b8' in reg['c']
mapping=json.loads((OUT/'jni_mapping.json').read_text(encoding='utf-8'))
for row in mapping['mapping']:
 if row['dynamic_candidates']:
  assert row['java_method'].startswith('Lwseemann/media/FFmpegMediaMetadataRetriever;->')
  row['status']='verified_dynamic_registration_static_path';row['registration_consumer']={'JNI_OnLoad_elf_va':'0x7504','helper_elf_va':'0x7428','table_elf_va':'0x15b50','count':15,'RegisterNatives_wrapper_elf_va':'0x748c','JNI_slot_offset':'0x6b8'}
 if '->splitYuvArrayToYAndUv(' in row['java_method']:
  row['implementation_candidate']={'library':'libllc.so','elf_va':'0x16e18','export':'_Z67Java_com_panasonic_jp_lumixlab_LlcApplication_splitYuvArrayToYAndUvP7_JNIEnvP8_jobjectP11_jbyteArrayS4_S4_ii',
    'reason':'C++ mangling differs from JNI name lookup; implementation exists but runtime binding not established'}
  row['status']='implementation_present_Cpp_mangled_binding_unresolved'
save('jni_mapping_verified.json',mapping)
send=selected['Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->x0()V'];si={i['offset_cu']:i for i in send['instructions']}
assert si[0x54]['opcode']=='new-array' and si[0x54]['registers']==[1,0]
assert si[0x61]['reference']=='Ljava/io/FileInputStream;->read([B)I' and si[0x61]['registers']==[3,1]
assert si[0x64]['reference']=='Ljava/io/FileInputStream;->close()V'
assert si[0x5e]['reference']=='Ljava/io/FileInputStream;->skip(J)J' and si[0x61]['opcode'].startswith('invoke')
assert si[0x78]['reference']=='Lg8/z0;->a(Lg8/k0;I[BI)Lg8/y0;' and si[0x78]['registers']==[2,3,1,0]
assert si[0x97]['reference'].startswith('LR5/h;->b(')
zipmethod=next(m for m in selected.values() if m['method'].startswith('Lcom/panasonic/jp/lumixlab/util/E1;->b('));zi={i['offset_cu']:i for i in zipmethod['instructions']}
assert zi[0x40]['opcode']=='if-eqz' and zi[0x40]['target_cu']==0x52 and zi[0x42]['target_cu']==0x49
assert zi[0x49]['reference']=='Ljava/io/File;->createNewFile()Z'
evidence=[]
for m,points in [(send,[0x45,0x54,0x5e,0x61,0x64,0x78,0x97]),(zipmethod,[0x5,0x34,0x3c,0x40,0x42,0x43,0x47,0x49,0x53,0x59,0x6e,0x75])]:
 for cu in points:evidence.append({'method':m['method'],'dex':m['dex'],'dex_byte_offset':location(m,cu),**next(i for i in m['instructions'] if i['offset_cu']==cu)})
save('critical_dex_evidence.json',{'verified_relations':['read buffer v1 passed unchanged to request-body factory','skip/read return lengths unused (no move-result)','valid parent directory flows to createNewFile; JADX high-level negation is wrong'],
 'instructions':evidence})
save('scope_verification.json',{'dex_definitions_independently_offset_checked':76901,'native_declarations':214,'jni_status':dict(collections.Counter(r['status'] for r in mapping['mapping'])),
 'jadx_error_events':42,'distinct_failed_methods':24,'structural_cfg_recovered':len(graphs),'ghidra_functions':len(ghidra),'ghidra_instruction_bytes_compared':bytecount,
 'negative_scope':'No verified firmware-byte-to-JNI flow in the explicitly traced download/unzip/request-body path; this does not exclude computed/reflection/indirect or platform-supplied paths elsewhere.',
 'device_io':False,'apk_or_firmware_modified':False,'target_program_executed':False})
print(json.dumps({'cfgs':len(graphs),'ghidra_functions':len(ghidra),'instruction_byte_comparisons':bytecount,'jni_status':dict(collections.Counter(r['status'] for r in mapping['mapping']))}))
