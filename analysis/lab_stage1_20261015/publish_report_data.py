"""Produce public metadata and scoped flow indexes; never copies vendor binaries/full source."""
import hashlib,json,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from dex_offsets import offsets
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];WORK=ROOT/'.research-local/stage1';OUT=HERE/'results'
SOURCE=Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])
def save(name,data):(OUT/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
preflight=json.loads((ROOT/'.research-local/stage1_preflight/inventory.json').read_text(encoding='utf-8'))
inputs=[]
for row in preflight['apks']:
 path=SOURCE/row['path']
 with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
 assert actual==row['sha256'] and path.stat().st_size==row['size']
 inputs.append({'kind':'APK','path_token':'<SOURCE_ROOT>/'+row['path'],'version':'3.1.0 versionCode 22','size':row['size'],'sha256':row['sha256'],
                'provenance':'existing Google Play delivery record; no fresh publisher/signature attestation','status':row['status'],'github_binary_present':False})
for kind,key in [('DEX','dex'),('ELF_ARM64','native')]:
 for row in preflight[key]:
  path=SOURCE/('extracted/base' if key=='dex' else 'extracted/arm64')/row['member']
  with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
  assert actual==row['sha256'] and path.stat().st_size==row['size']
  inputs.append({'kind':kind,'member':row['member'],'container':row['container'],'version':'3.1.0 versionCode 22','size':row['size'],'sha256':actual,
                 'status':'verified_again_after_analysis; matches verified APK member','github_binary_present':False})
save('inputs.json',{'scope':'All 25 APK/DEX/SO binary inputs used in stage 1','vendor_code_executed':False,'input_files':inputs,
 'availability':{'local_verified':'5 APK + 2 DEX + 18 SO','github':'reports, hashes and selected previous evidence; original proprietary APK/DEX/SO excluded',
 'historical_only':'APKPure XAPK and mdpi split absent; 60/61 corrected-source files match only after LF normalization; P2 source variant remains',
 'body_side_missing':'S5M2 receiver/daemon/authentication/decoder and deployment evidence not supplied by client APK; S1M2 evidence is not substituted'}})
methods=[json.loads(s) for s in (WORK/'dex_index_v2.jsonl').open(encoding='utf-8')];selected={m['method']:m for m in map(json.loads,(WORK/'selected_instructions.jsonl').open(encoding='utf-8'))}
native_ids={m['method'] for m in methods if m['native']}
locations={d:offsets(SOURCE/'extracted/base'/d) for d in ['classes.dex','classes2.dex']}
def entry(m,c):return {'offset_cu':c['offset_cu'],'dex_byte_offset':hex(locations[m['dex']][m['method']]['insns_offset']+2*c['offset_cu']),
                       'target':c['reference'],'registers':c['registers']}
core=[]
for m in selected.values():
 name=m['method']
 if name.startswith(('LR5/d;->c(','LR5/e;->b(','LR5/f;->b(','LR5/h;->b(','Lz5/j4;->c(','Lg8/y0;->','Lg8/z0;->a(',
                     'Lcom/panasonic/jp/lumixlab/util/E1;->b(','Lcom/panasonic/jp/lumixlab/util/E1;->c(',
                     'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->x0()',
                     'Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->z0(', 'LY5/h;->run()','Lh6/d;->verify(',
                     'Lcom/panasonic/jp/lumixlab/util/b0;->y(')):
  core.append({'method':name,'dex':m['dex'],**locations[m['dex']][name],'call_sites':[entry(m,c) for c in m['calls']],
               'direct_native_calls':[entry(m,c) for c in m['calls'] if c['reference'] in native_ids]})
save('firmware_dataflow.json',{'coverage':'Explicit method bodies listed below; callbacks manually linked by constructor/receiver types and fields. Synthetic multi-case Runnable methods are context-sensitive, not all cases treated as update paths.',
 'methods':core,'path_reads_and_writes':[{'caller':m['method'],'dex':m['dex'],**entry(m,c)} for m in methods for c in m['calls'] if any(s in c['reference'] for s in ['UpdateInfoEntity;->getUpdateDownloadPath','UpdateInfoEntity;->setUpdateDownloadPath'])],
 'conclusions':[{'status':'已驗證','claim':'x0 read array register v1 is supplied unchanged to g8/z0 request-body factory; return values from skip/read are not consumed'},
                {'status':'已驗證','claim':'z5/j4.c selects first non-null isFile entry and resolves its basename against extraction root; no extension/header/signature predicate in that selection region'},
                {'status':'已驗證','claim':'E1.b valid parent branches to createNewFile; generated Java boolean grouping differs'},
                {'status':'已驗證','claim':'h6/d.verify hashes peer certificate encoded bytes, not firmware file bytes'},
                {'status':'尚未確認','claim':'No complete global absence proof for computed, reflective, optional, platform-provided or body-side firmware processing'}]})
loads=json.loads((OUT/'library_load_sites.json').read_text(encoding='utf-8'))
for row in loads:
 m=selected[row['caller']];instruction=next(i for i in m['instructions'] if i['offset_cu']==row['offset_cu']);reg=instruction['registers'][-1]
 earlier=[i for i in m['instructions'] if i['offset_cu']<row['offset_cu'] and i['registers'] and i['registers'][0]==reg]
 last=earlier[-1] if earlier else None
 if last and last['opcode'].startswith('const-string'):
  row['constant_argument']=last['reference'];row['definition_offset_cu']=last['offset_cu'];row['constant_argument_status']='verified_immediate_register_definition'
 else:row['constant_argument_status']='computed_or_parameter_argument; raw method instructions preserved locally'
save('library_load_sites_verified.json',loads)
log=(WORK/'jadx_replay.log').read_text(encoding='utf-8',errors='replace')
excerpt='\n'.join(line for line in log.splitlines() if line.startswith('ERROR - ') and (' in method:' in line or 'Method:' in line or 'count: 42' in line))+'\n'
(OUT/'jadx_error_excerpt.txt').write_text(excerpt,encoding='utf-8',newline='\n')
fail=json.loads((OUT/'jadx_failures.json').read_text(encoding='utf-8'))
table=['# JADX 1.5.6 失敗方法核對','', '42 錯誤事件對應 24 個不同方法。全部已恢復原始指令與結構 CFG；未把 CFG 有效等同完整高階語義恢復。','',
       '| Raw DEX 方法 | DEX / code_item | Code units | 事件數 | 修復界線 |','|---|---|---:|---:|---|']
for row in fail['methods']:
 label='原始指令／CFG 已恢復；完整語義仍待覆核'
 table.append('| `'+row['method']+'` | '+row['dex']+' / `'+hex(row['location']['code_item_offset'])+'` | '+str(row['code_units'])+' | '+str(len(row['error_events']))+' | '+label+' |')
(HERE/'FAILED_METHODS.md').write_text('\n'.join(table)+'\n',encoding='utf-8',newline='\n')
tools=json.loads((WORK/'tool_verification.json').read_text(encoding='utf-8'))
save('tools.json',{'tools':tools,'official_metadata_checked':'2026-10-15','origins':['https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build',
 'https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse'],
 'jadx':'1.5.6, official archive SHA-256 545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974; dexlib2 and Gson bundled in verified jar',
 'python':'CPython 3.12.14; pyelftools 0.33; Capstone 5.0.9 inherited from verified offline environment'})
save('git_snapshot.json',{'branch':subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip(),
 'starting_environment_commit':'4c83e428ee586aa8166e4da350a0441b2b27fd26','fork_main':subprocess.check_output(['git','rev-parse','origin/main'],cwd=ROOT,text=True).strip(),
 'upstream_main':subprocess.check_output(['git','rev-parse','upstream/main'],cwd=ROOT,text=True).strip(),
 'main_divergence':subprocess.check_output(['git','rev-list','--left-right','--count','origin/main...upstream/main'],cwd=ROOT,text=True).strip(),
 'original_work_preserved':True,'untracked_downloads_and_attachments_not_staged':True})
print('PASS: public metadata, 25 post-analysis input hashes, flow indexes and 24-method repair table written')
