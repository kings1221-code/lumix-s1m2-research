"""Bounded input and saved-evidence audit, without another decompilation or scan."""
import collections
import gzip
import re
import subprocess
import sys
from common import *

REQUIRED=('README INPUT_MANIFEST APK_STRUCTURE FUNCTION_MODULE_MAP DEX_ANALYSIS '
          'JNI_NATIVE_MAP ARM64_ANALYSIS CRYPTO_AND_ENCODING_MAP COMMUNICATION_MAP '
          'FIRMWARE_UPDATE_MAP UNRESOLVED REPRODUCE COVERAGE PROGRESS').split()

def zipped(name):
    with gzip.open(RESULTS/name,'rt',encoding='utf-8') as f:return json.load(f)

def main():
    prior=[]
    for stage in ('lab_stage1_20261015','s5m2_stage2_20261016'):
        here=ROOT/'analysis'/stage
        manifest=load(here/'delivery_manifest.json')
        for r in manifest['files']:
            p=(here/r['path']).resolve();assert p.is_relative_to(here.resolve())
            assert file_id(p)=={k:r[k] for k in ('size','sha256')},r['path']
        prior.append({'stage':stage,'artifact_count':len(manifest['files']),'status':'PASS'})
    inputs=load(RESULTS/'input_manifest.json')['inputs']
    assert len(inputs)==25
    for r in inputs:
        if r['kind']=='APK':p=Path(r['path_token'].replace('<SOURCE_ROOT>',str(SOURCE)))
        elif r['kind']=='DEX':p=SOURCE/'extracted/base'/r['member']
        else:p=SOURCE/'extracted/arm64'/r['member']
        assert file_id(p)=={k:r[k] for k in ('size','sha256')},p.name
    apks=zipped('apk_members.json.gz')['apks']
    assert len(apks)==5 and sum(len(a['members']) for a in apks)==4867
    for a in apks:
        r=next(r for r in inputs if r['kind']=='APK' and r['path_token'].endswith('/'+a['apk']))
        assert a['sha256']==r['sha256'] and a['size']==r['size']
        assert len({m['path'] for m in a['members']})==a['member_count']
    dex=zipped('dex_structure.json.gz');summary=load(RESULTS/'dex_summary.json')
    assert len(dex['classes'])==summary['classes']==14812
    assert sum(len(c['fields']) for c in dex['classes'])==summary['fields']==48914
    assert len(dex['methods'])==summary['method_definitions']==76901
    assert len(dex['invoke_edges'])==summary['invoke_sites']==349415
    assert len(dex['call_targets'])==summary['call_targets']==48522
    assert len(zipped('dex_strings.json.gz')['strings'])==summary['strings']==73540
    assert len({m['method'] for m in dex['methods']})==76901
    for caller,cu,target,opcode in dex['invoke_edges']:
        assert 0<=caller<len(dex['methods']) and 0<=target<len(dex['call_targets'])
        assert 0<=cu<dex['methods'][caller]['code_units'] and opcode.startswith('invoke-')
    assert len(zipped('elf_structure.json.gz')['libraries'])==18
    coverage=load(RESULTS/'coverage.json');assert len(coverage['native_libraries'])==18
    assert coverage['selected_native_functions_unique_including_prior']==61
    assert sum(r['selected_ghidra_functions_including_prior'] for r in coverage['native_libraries'])==61
    assert len(load(RESULTS/'jni_unresolved_update.json')['entries'])==2
    old=load(ROOT/'analysis/lab_stage1_20261015/results/jni_mapping_verified.json')['mapping']
    counts=collections.Counter(r['status'] for r in old)
    assert len(old)==214 and counts['static_symbol_correspondence']==197
    assert counts['verified_dynamic_registration_static_path']==15
    failed=load(RESULTS/'failed_method_progress.json')
    assert failed['error_events']==42 and failed['distinct_methods']==len(failed['methods'])==24
    assert sum('new partial semantic' in r['status'] for r in failed['methods'])==1
    gaps=load(RESULTS/'resource_decode_gaps.json')['logs']
    assert sum(r['unresolved_reference_events'] for r in gaps)==692
    assert len({s for r in gaps for s in r['unique_unresolved_ids']})==427
    assert all(r['exit_code']==0 for r in load(RESULTS/'apktool_execution.json')['apks'])
    for r in load(RESULTS/'apktool_execution.json')['apks']:
        assert file_id(WORK/(r['apk']+'.apktool.log'))==r['log_id']
    assert all(r['opcode_sequence_match'] for r in load(RESULTS/'smali_crosscheck.json')['methods'])
    assert len(load(RESULTS/'callable_case_evidence.json')['methods'])==6
    assert len(load(RESULTS/'semantic_dex_evidence.json')['methods'])==12
    native=load(RESULTS/'native_evidence.json')
    assert sum(len(r['selected_functions']) for r in native['libraries'])==11
    assert native['instruction_rows_original_ELF_checked']==1543
    fixed=load(RESULTS/'prototype_correction.json')
    actual=load(WORK/'native_prototype_fixed/prototype_fixed.json')
    assert sha(actual['c'].encode())==fixed['fixed_generated_c_sha256']
    assert fixed['fixed_call_excerpt'] in actual['c'] and fixed['fixed_call_excerpt'].count(',')==2
    # Recheck the saved independent byte/CRC controls; no Ghidra or target execution.
    for script in ('dispatch_case.py','verify_findings.py','final_metadata.py'):
        subprocess.run([sys.executable,str(BASE/'scripts'/script)],check=True)
    for name in REQUIRED:
        assert (BASE/(name+'.md')).stat().st_size>100,name
    # Check decoded public metadata as well as text, not just filenames.
    checked=0
    sensitive=(r'(?i)[A-Z]:[\\/]Users[\\/]',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
               r'(?i)authorization:\s*Bearer\s+[A-Za-z0-9_./+=-]{20,}',r'gh[pousr]_[A-Za-z0-9]{30,}',
               r'(?i)Set-Cookie:\s*[^\s]{20,}')
    for p in BASE.rglob('*'):
        if not p.is_file() or 'local' in p.relative_to(BASE).parts or '__pycache__' in p.parts:continue
        assert p.suffix.lower() not in ('.apk','.dex','.so','.bin','.jar','.sqlite','.smali','.class'),p.name
        b=gzip.decompress(p.read_bytes()) if p.name.endswith('.json.gz') else p.read_bytes()
        text=b.decode('utf-8');assert '\ufffd' not in text,p.name
        for pattern in sensitive:assert not re.search(pattern,text),('publication guard',p.name,pattern)
        if p.suffix=='.md':
            for target in re.findall(r'\]\(([^)]+)\)',text):
                if '://' not in target and not target.startswith('#'):
                    assert (p.parent/target.split('#')[0]).exists(),(p.name,target)
        checked+=1
    save(RESULTS/'final_validation.json',{'status':'PASS','prior_deliveries':prior,'original_inputs_sha256_rechecked':25,
         'APK_member_metadata_count':4867,'DEX_structure_consistency':True,'JNI_counts':[197,15,2],
         'new_selected_native_functions':11,'cumulative_distinct_selected_native_functions':61,
         'unresolved_resource_ids':427,'unresolved_JNI_bindings':2,'failed_methods_full_semantics_completed':0,
         'saved_raw_controls_rechecked':['6 dispatcher methods','12 semantic methods','1543 ELF instruction rows','2 Baksmali opcode sequences','PNG CRC control'],
         'publication_guard':'UTF-8 text/decoded JSON-gzip checked for user paths/private-key/Bearer/GitHub-token/Set-Cookie patterns; original executable extensions excluded',
         'limits':'Publication guard is bounded; checks establish input/evidence consistency, not whole-App semantics. No target program or camera I/O.',
         'D_E_F_G':'waiting for user review'})
    print('PASS: 25 original inputs; inherited deliveries; current structural/byte controls; publication metadata guard')

if __name__=='__main__':main()
