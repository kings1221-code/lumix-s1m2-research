"""Cross-validate saved research and publication boundary; not whole-App semantics."""
import collections,gzip,re,struct,subprocess,sys
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from common import *
from dynamic import flow
def synthetic_cfg_controls():
    def i(at,op,regs=(),width=1,**kw):return dict(offset_cu=at,opcode=op,registers=list(regs),width_cu=width,**kw)
    # Differing constants at a join must not be reported as one resolved target.
    m={'instructions':[i(0,'if-eqz',[9],target_cu=3),i(1,'const-string',[0],reference='a.A'),i(2,'goto',target_cu=4),i(3,'const-string',[0],reference='b.B'),i(4,'return-object',[0]) ]}
    assert 0 not in flow(m)[4]
    m['instructions'][3]['reference']='a.A';assert flow(m)[4][0]==('str','a.A')
    # A filled-new-array reads its arguments; it must not clobber the first one.
    m={'instructions':[i(0,'const/4',[2],literal=1),i(1,'filled-new-array',[2]),i(2,'move-result-object',[0]),i(3,'return',[2])]}
    assert flow(m)[3][2]==('int',1)
    # Handler merges preserve an untouched selector but invalidate a throwing destination.
    m={'instructions':[i(0,'const/4',[2],literal=1),i(1,'iget-object',[0,3],reference='Lx;->f:Ljava/lang/Object;'),i(2,'return',[2]),i(3,'move-exception',[0]),i(4,'return',[2])],
       'try_blocks':[{'start_cu':1,'count_cu':1,'handlers':[{'target_cu':3}]}]}
    assert flow(m)[4][2]==('int',1) and 0 not in flow(m)[3]
    return 4
def main():
    previous=[]
    for name in ('lab_stage1_20261015','s5m2_stage2_20261016','lumix_lab_full_reverse'):
        path=ROOT/'analysis'/name
        subprocess.run([sys.executable,str(path/'verify_delivery.py')],check=True)
        previous.append({'stage':name,'artifacts':len(load(path/'delivery_manifest.json')['files'])})
    for r in load(RESULTS/'input_manifest.json')['inputs']:
        p=Path(r['path_token'].replace('<SOURCE_ROOT>',str(SOURCE))) if r['kind']=='APK' else SOURCE/'extracted/base'/r['member'] if r['kind']=='DEX' else SOURCE/'extracted/arm64'/r['member']
        assert identity(p)=={k:r[k] for k in ('size','sha256')}
    dex=load(RESULTS/'selected_dex_evidence.json.gz');assert len(dex['methods'])==2231 and len(dex['invoke_operands_checked'])==11280
    known={(r['method'],r['cu'],r['target']) for r in dex['invoke_operands_checked']}
    api=load(RESULTS/'api_usage.json.gz')['sites'];assert len(api)==5375
    assert all((r['method'],r['cu'],r['target']) in known for r in api)
    dyn=load(RESULTS/'dynamic_classification.json')['candidates'];assert len(dyn)==243
    assert sum(r['resolution']=='exact literal target recovered' for r in dyn)==95
    assert len(load(RESULTS/'r8_callable_cases.json')['caller_cases'])==5
    assert len(load(RESULTS/'failed_method_ranking.json')['methods'])==23
    assert len(load(RESULTS/'java_dataflows.json')['flows'])==14
    resource=load(RESULTS/'resource_raw_consumers.json');rawrefs=resource['ARSC_value_references']+resource['AXML_attribute_references']
    found=collections.Counter(int(r['target_id'],16) for r in rawrefs);warn=collections.Counter()
    for p in (ROOT/'.research-local/full_reverse').glob('*.apktool.log'):
        for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
            if (m:=re.search(r'Unresolved resource reference:.*?, id=(0x[0-9a-f]+), type=',line)):warn[int(m.group(1),16)]+=1
    assert found==warn and len(found)==427 and sum(found.values())==692
    assert len(load(RESULTS/'resource_resolution.json')['entries'])==428
    # Capstone independently decodes each reported BL/PLT instruction mapping.
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);md.detail=True;bl=0;plt=0
    from elftools.elf.elffile import ELFFile
    for lib in load(RESULTS/'native_import_calls.json.gz')['libraries']:
        p=SOURCE/'extracted/arm64/lib/arm64-v8a'/lib['library'];data=p.read_bytes()
        with p.open('rb') as f:
            elf=ELFFile(f);segments=list(elf.iter_segments())
            def offset(va):
                s=next(s for s in segments if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']);return s['p_offset']+va-s['p_vaddr']
            for c in lib['direct_BL_calls']:
                va=int(c['elf_va'],16);assert data[c['file_offset']:c['file_offset']+4].hex()==c['raw_hex']
                i=next(md.disasm(bytes.fromhex(c['raw_hex']),va));assert i.mnemonic=='bl' and i.operands[0].imm==int(c['target_PLT_va'],16);bl+=1
            for c in lib['selected_PLT_entries']:
                va=int(c['plt_va'],16);raw=bytes.fromhex(c['raw_hex']);assert data[offset(va):offset(va)+16]==raw
                ins=list(md.disasm(raw,va));assert ins[0].mnemonic=='adrp' and ins[1].mnemonic=='ldr'
                assert ins[0].operands[1].imm+ins[1].operands[1].mem.disp==int(c['GOT_va'],16);plt+=1
    assert bl==2428 and plt==357
    assert load(RESULTS/'native_evidence.json')['total_instruction_rows_original_ELF_checked']==1752
    cov=load(RESULTS/'native_coverage.json');assert cov['unique_selected_functions']==65 and cov['new_CFG_functions']==13
    assert load(RESULTS/'lut_synthetic.json')['model_cases']==1044
    assert len(load(RESULTS/'jni_gap_audit.json')['still_unresolved'])==2
    controls=synthetic_cfg_controls()
    # No raw target binary, decompiled listing, user path or credential value allowed.
    patterns=(r'(?i)[A-Z]:[\\/]Users[\\/]',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'gh[pousr]_[A-Za-z0-9]{30,}',
              r'(?i)authorization:\s*Bearer\s+[A-Za-z0-9_./+=-]{20,}',r'(?i)Set-Cookie:\s*[^\s]{20,}')
    for p in BASE.rglob('*'):
        if not p.is_file() or 'local' in p.relative_to(BASE).parts or '__pycache__' in p.parts:continue
        assert p.suffix.lower() not in ('.apk','.dex','.so','.bin','.jar','.sqlite','.smali','.class'),p.name
        text=(gzip.decompress(p.read_bytes()) if p.name.endswith('.json.gz') else p.read_bytes()).decode('utf-8')
        assert '\ufffd' not in text,p.name
        for pattern in patterns:assert not re.search(pattern,text),('publication guard',p.name)
        if p.suffix=='.md':
            for target in re.findall(r'\]\(([^)]+)\)',text):
                if '://' not in target and not target.startswith('#'):assert (p.parent/target.split('#')[0]).exists(),(p.name,target)
    save(RESULTS/'validation.json',{'status':'PASS','inherited_deliveries':previous,'original_inputs_SHA256':25,'independent_Dex_bodies':2231,
      'independent_invoke_operands':11280,'API_sites_covered':5375,'dynamic_sites':243,'exact_literal_targets':95,'verified_finite_set_additional_sites':1,
      'CFG_synthetic_controls':controls,'resource_reference_multiset_matches_original_692_warnings':True,'resource_IDs_resolved':427,
      'Capstone_BL_crosschecks':bl,'Capstone_PLT_GOT_crosschecks':plt,'Ghidra_function_instruction_rows':1752,'LUT_model_cases':1044,
      'JNI_unresolved':2,'limits':'Input/publication/operand/model consistency only; no target App/SO execution, no camera/service I/O; full semantic completeness not asserted.'})
    print('PASS D/F checkpoint: inherited delivery, inputs, DEX operands, native BL/PLT, exact resource warning multiset, bounded models and publication guard')
if __name__=='__main__':main()
