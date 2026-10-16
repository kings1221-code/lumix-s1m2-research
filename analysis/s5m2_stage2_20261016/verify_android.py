"""Verify targeted DEX evidence and publish metadata, not full vendor code."""
import importlib.util
import json
from pathlib import Path
from common import ROOT, WORK, RESULTS, file_id, digest, save, load, config

F='Lcom/panasonic/jp/lumixlab/controller/fragment/FirmwareUpdateDetailFragment;->'
WINDOWS={
 F+'x0()V': [(0x41,0x9b)],
 F+'r0(ILjava/lang/String;)V': [(0xd,0x38),(0x52,0x65)],
 F+'q0()V': [(0,0x39)], F+'v0()Z':[(0,0x1b)],
 'Lz5/j4;->c(Lcom/panasonic/jp/lumixlab/bean/CommunityDownloadInfoBean;)V':[(0x62,0xa0),(0xc3,0xc8)],
 'Lz5/i4;->onClick(Landroid/view/View;)V':[(0x5f,0x7d)],
 'LR5/f;->b(Loa/h;Loa/s0;)V':[(0x5f,0x88)],
 'LR5/g;->b(Loa/h;Loa/s0;)V':[(0x20,0x3c)],
 'Lu8/j;->h0([BII)V':[(0x15,0x2f)],
 'Lz7/q;->c(III[B[B)V':[(0,0xf)],
 'LH5/d;->onCharacteristicChanged(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;)V':[(0,0x12),(0x4c6,0x50b)],
 'Lz5/n4;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V':[(0x1a,0x3f)],
}

def rows(path):
    with path.open(encoding='utf-8') as f:
        return [json.loads(s) for s in f]

def main():
    source=Path(config()['source_root'])/'extracted/base'
    spec=importlib.util.spec_from_file_location('stage1_dex_offsets',ROOT/'analysis/lab_stage1_20261015/dex_offsets.py')
    parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
    offsets={name:parser.offsets(source/name) for name in ('classes.dex','classes2.dex')}
    binary={name:(source/name).read_bytes() for name in offsets}
    selected=rows(WORK/'android_instructions_final.jsonl')+rows(WORK/'android_paths_extra.jsonl')
    index={r['method']:r for r in selected}
    assert len(index)==len(selected)==81
    saved=rows(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
    native={r['method'] for r in saved if r['native']}
    summaries=[];excerpts=[];direct_native=[]
    for r in selected:
        loc=offsets[r['dex']][r['method']]
        assert loc['code_units']==r['code_units'] and loc['access_flags']==r['access_flags']
        assert sum(i['width_cu'] for i in r['instructions'])==r['code_units']
        starts={i['offset_cu'] for i in r['instructions']}
        for i in r['instructions']:
            assert all(0<=v<r['registers'] for v in i['registers'])
            if 'target_cu' in i:
                assert i['target_cu'] in starts
        start=loc['insns_offset'];end=start+2*r['code_units']
        raw=binary[r['dex']][start:end]
        assert len(raw)==2*r['code_units']
        summaries.append({'method':r['method'],'dex':r['dex'],'location':loc,
                          'registers':r['registers'],'instruction_bytes_sha256':digest(raw),
                          'calls':r['calls'],
                          'callers_in_saved_stage1_index':
                            [{'method':s['method'],'dex':s['dex'],'offset_cu':c['offset_cu']}
                             for s in saved for c in s['calls'] if c['reference']==r['method']]})
        direct_native.extend({'caller':r['method'],**c} for c in r['calls'] if c['reference'] in native)
        for lo,hi in WINDOWS.get(r['method'],[]):
            ins=[i for i in r['instructions'] if lo<=i['offset_cu']<hi]
            assert ins and ins[0]['offset_cu']==lo
            excerpt=[]
            for i in ins:
                at=start+2*i['offset_cu']
                excerpt.append({**i,'file_offset':at,'raw_hex':binary[r['dex']][at:at+2*i['width_cu']].hex()})
            excerpts.append({'method':r['method'],'dex':r['dex'],'location':loc,
                             'requested_range_cu':[lo,hi],'instructions':excerpt})
    x=index[F+'x0()V'];by={i['offset_cu']:i for i in x['instructions']}
    assert by[0x45]['opcode']=='mul-int' and by[0x54]['opcode']=='new-array'
    assert by[0x5e]['reference']=='Ljava/io/FileInputStream;->skip(J)J'
    assert by[0x61]['reference']=='Ljava/io/FileInputStream;->read([B)I'
    assert by[0x64]['reference']=='Ljava/io/FileInputStream;->close()V'
    assert by[0x61]['registers']==[3,1] and by[0x78]['registers']==[2,3,1,0]
    assert by[0x78]['reference']=='Lg8/z0;->a(Lg8/k0;I[BI)Lg8/y0;'
    assert by[0x5e+by[0x5e]['width_cu']]['opcode']!='move-result-wide'
    assert by[0x61+by[0x61]['width_cu']]['opcode']!='move-result'
    r=index[F+'r0(ILjava/lang/String;)V'];byr={i['offset_cu']:i for i in r['instructions']}
    assert byr[0x11]['reference']==F.split('->')[0]+'->x0:I'
    assert byr[0x15]['opcode']=='if-ge' and byr[0x15]['target_cu']==0x1f
    assert byr[0x1f]['opcode']=='if-ne' and byr[0x28]['reference']=='DETAIL_TRANSFERRED'
    j=index['Lz5/j4;->c(Lcom/panasonic/jp/lumixlab/bean/CommunityDownloadInfoBean;)V']
    bj={i['offset_cu']:i for i in j['instructions']}
    assert bj[0x80]['reference']=='Ljava/io/File;->getName()Ljava/lang/String;'
    assert bj[0x96]['reference']=='Ljava/nio/file/Path;->resolve(Ljava/lang/String;)Ljava/nio/file/Path;'
    assert bj[0x9e]['opcode']=='goto' and bj[0x9e]['target_cu']==0xa0
    assert not direct_native, direct_native
    save(RESULTS/'android_method_index.json',{'scope':'81 selected methods from existing stage1 reference index; location/length/register/branch checks, not whole-method semantic recovery',
         'input_dex':[{ 'file':n,**file_id(source/n)} for n in binary], 'methods':summaries})
    save(RESULTS/'android_instruction_evidence.json',{'coordinate_rule':'file_offset = code_item_offset + 16 + 2 * CU; CU is 16-bit',
         'excerpts':excerpts,'checked_rules':['single skip/read return values ignored','same byte[] is passed to request body factory',
          'success increments index, checks count, then next chunk or DETAIL_TRANSFERRED','selector discards parent and uses basename under extraction root'],
         'direct_calls_to_214_app_native_declarations_in_selected_methods':direct_native,
         'negative_scope':'Only explicit invoke references in these selected methods. Indirect/reflection/platform implementations and unreviewed paths are not excluded.'})
    synthetic=load(WORK/'synthetic/result.json')
    save(RESULTS/'synthetic_controls.json',synthetic)
    save(RESULTS/'android_verification.json',{'selected_methods':len(selected),'input_dex':[{'file':n,**file_id(source/n)} for n in binary],
         'method_offsets_lengths_registers_and_encoded_branch_targets_checked':True,
         'raw_instruction_excerpts':len(excerpts),'synthetic_result_id':file_id(WORK/'synthetic/result.json'),
         'vendor_program_executed':False,'device_io':False,
         'limits':'Synthetic own reconstruction runs on host JDK25; DEX assertions establish only listed local facts, not a complete App semantic proof.'})
    print('PASS: 81 selected DEX methods, independent offsets and critical operand/branch assertions; own synthetic controls saved')

if __name__=='__main__':
    main()
