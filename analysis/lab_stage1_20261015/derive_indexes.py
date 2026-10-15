"""Derive auditable native/call/failed-method indexes; all source inputs remain read-only."""
import collections,hashlib,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from dex_offsets import offsets
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];WORK=ROOT/'.research-local/stage1'
SOURCE=Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])
OUT=HERE/'results';OUT.mkdir(exist_ok=True)
def save(name,data): (OUT/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
methods=[json.loads(s) for s in (WORK/'dex_index_v2.jsonl').open(encoding='utf-8')]
byid={m['method']:m for m in methods};assert len(byid)==len(methods)
raw={dex:offsets(SOURCE/'extracted/base'/dex) for dex in ['classes.dex','classes2.dex']}
for m in methods:
 info=raw[m['dex']][m['method']];assert info['code_units']==m['code_units'] and info['access_flags']==m['access_flags']
 m['location']=info
def site(m,c):
 return {'caller':m['method'],'dex':m['dex'],'offset_cu':c['offset_cu'],'dex_byte_offset':hex(m['location']['insns_offset']+2*c['offset_cu']),
         'opcode':c['opcode'],'argument_registers':c['registers']}
callers=collections.defaultdict(list)
for m in methods:
 for c in m['calls']:callers[c['reference']].append(site(m,c))
native=[m for m in methods if m['native']]
save('dex_native_methods.json',{'input_version':'LUMIX Lab 3.1.0 versionCode 22','definitions_checked':len(methods),'native_count':len(native),
 'methods':[{'method':m['method'],'dex':m['dex'],'access_flags':m['access_flags'],'method_index':m['location']['method_index'],'callers':callers[m['method']]} for m in native]})
libs=json.loads((WORK/'elf_inventory.json').read_text(encoding='utf-8'))['libraries']
def mangle(s):
 result=''
 for c in s:
  if c.isascii() and c.isalnum():result+=c
  elif c=='/':result+='_'
  elif c=='_':result+='_1'
  elif c==';':result+='_2'
  elif c=='[':result+='_3'
  else:result+='_0'+format(ord(c),'04x')
 return result
mapping=[];used=set()
for m in native:
 cls,rest=m['method'].split('->');name,sig=rest.split('(',1);sig='('+sig
 short='Java_'+mangle(cls[1:-1])+'_'+mangle(name);long=short+'__'+mangle(sig[1:sig.index(')')])
 matches=[{'library':l['library'],'export':s['name'],'elf_va':s['va'],'size':s['size'],'kind':'static_jni_symbol'} for l in libs for s in l['static_jni_exports'] if s['name'] in (short,long)]
 for x in matches:used.add((x['library'],x['export']))
 dynamic=[{'library':l['library'],**t} for l in libs for t in l['dynamic_jni_candidates'] if t['name']==name and t['signature']==sig]
 mapping.append({'java_method':m['method'],'dex':m['dex'],'static_matches':matches,'dynamic_candidates':dynamic,
                 'status':'static_symbol_correspondence' if matches else 'dynamic_candidate_pending_consumer' if dynamic else 'unresolved_in_18_libraries'})
save('jni_mapping.json',{'scope':'Full DEX native declarations versus full 18-library dynsym and candidate tables; symbol matches alone do not prove function semantics',
 'mapping':mapping,'unmatched_exports':[{'library':l['library'],**s} for l in libs for s in l['static_jni_exports'] if (l['library'],s['name']) not in used]})
loads=[];targets=set()
for m in methods:
 for c in m['calls']:
  if c['reference'].startswith(('Ljava/lang/System;->load','Ljava/lang/Runtime;->load')):
   loads.append({**site(m,c),'target':c['reference'],'prior_string_constants':[s for s in m['strings'] if s['offset_cu']<c['offset_cu']][-5:],
                 'constant_argument_status':'requires_register_definition_check'})
   targets.add(m['method'])
save('library_load_sites.json',loads)
apis=[]
for m in methods:
 for a in m['annotations']:
  value=a['values'].get('value')
  if isinstance(value,str) and ('firmware' in value.lower()) and a['type'].startswith('Lsa/'):
   apis.append({'method':m['method'],'annotation':a,'callers':callers[m['method']]});targets.add(m['method'])
   targets.update(c['caller'] for c in callers[m['method']])
save('firmware_api_calls.json',apis)
primitives={'B':'byte','C':'char','D':'double','F':'float','I':'int','J':'long','S':'short','V':'void','Z':'boolean'}
def types(desc):
 result=[]
 while desc:
  arrays=0
  while desc[0]=='[':arrays+=1;desc=desc[1:]
  if desc[0]=='L':end=desc.index(';');s=desc[1:end].replace('/','.');desc=desc[end+1:]
  else:s=primitives[desc[0]];desc=desc[1:]
  result.append(s+'[]'*arrays)
 return result
def human(name):
 cls,rest=name.split('->');n,desc=rest.split('(',1);p,ret=desc.split(')')
 return cls[1:-1].replace('/','.')+'.'+n+'('+', '.join(types(p))+'):'+types(ret)[0]
human_to_raw={human(m['method']):m['method'] for m in methods}
log=(WORK/'jadx_replay.log').read_text(encoding='utf-8',errors='replace')
summaries=re.findall(r'^ERROR -   Method: (.+)$',log,re.M)
events=re.findall(r'^ERROR - (.+? in method: (.+?), file: (classes\d*\.dex).*)$',log,re.M)
failures=[]
for h in summaries:
 name=human_to_raw[h.strip()];m=byid[name];targets.add(name)
 failures.append({'method':name,'jadx_label':h,'dex':m['dex'],'location':m['location'],'code_units':m['code_units'],
                  'error_events':[e[0] for e in events if e[1]==h],'recovery_status':'raw_DEX_instructions_and_CFG_to_be_verified',
                  'invoke_count':len(m['calls']),'unique_call_targets':sorted({c['reference'] for c in m['calls']})})
save('jadx_failures.json',{'jadx_version':'1.5.6','exit_code':int((WORK/'jadx_exit.txt').read_text()),'error_events':len(events),'distinct_failed_methods':len(failures),
 'historical_log':'analysis/lumix_lab_jadx_20261008.log only preserves total 42, not per-method identities','methods':failures})
for m in methods:
 if m['method'].startswith(('LR5/','Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdate','Lcom/panasonic/jp/lumixlab/util/E1;','Lz5/j4;','Lg8/y0;','Lg8/z0;','Lf5/P2;')):targets.add(m['method'])
 for c in m['calls']:
  if any(s in c['reference'] for s in ['UpdateInfoEntity;->getUpdateDownloadPath','UpdateInfoEntity;->setUpdateDownloadPath']):targets.add(m['method'])
 if m['method'].startswith(('Lcom/panasonic/jp/lumixlab/util/b0;->A(','Lcom/panasonic/jp/lumixlab/util/b0;->M(','Lcom/panasonic/jp/lumixlab/util/b0;->y(',
                            'Lcom/panasonic/jp/lumixlab/util/V;->e(','Lh6/d;->verify(')):targets.add(m['method'])
save('selected_method_locations.json',[{'method':n,'dex':byid[n]['dex'],**byid[n]['location']} for n in sorted(targets)])
(WORK/'dex_targets.txt').write_text('\n'.join(sorted(targets))+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'methods':len(methods),'native':len(native),'mapping_status':dict(collections.Counter(m['status'] for m in mapping)),
                 'load_sites':len(loads),'error_events':len(events),'failed_methods':len(failures),'selected_dump_methods':len(targets)}))
