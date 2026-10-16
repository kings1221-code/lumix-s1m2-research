"""Cross-check published metadata; optionally verify current raw inputs again.
No analysis expansion or device I/O.
"""
import argparse
import collections
import zipfile
from pathlib import Path
from common import ROOT, WORK, RESULTS, file_id, digest, load, save, config

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--with-inputs',action='store_true')
    p.add_argument('--record',action='store_true')
    a=p.parse_args()
    inputs=load(RESULTS/'inputs.json')
    assert len(inputs['inputs'])==inputs['input_identity_count']==35
    stage1=load(RESULTS/'stage1_preservation.json')
    assert stage1['actual_error_events']==42 and stage1['distinct_failed_methods']==24
    assert stage1['jni_counts_recomputed_from_214_rows']==stage1['jni_saved_scope']['jni_status']
    firmware=load(RESULTS/'firmware_structure.json')
    for label,im in firmware['images'].items():
        assert im['model']=='MC8223' and im['payload_start']==0x1800
        assert im['trailing_unassigned_bytes']==0
        assert im['rows'][-1]['constant_content']=='all_ff' and im['rows'][-1]['size']==131072
        assert len(im['rows'])==im['directory_count']
        assert im['regions']['directory_to_payload_gap']['all_zero']
    expected={'S5M2_V31':54,'S5M2_V37':58}
    assert {k:v['directory_count'] for k,v in firmware['images'].items()}==expected
    pairs=firmware['comparison']['pairs']
    assert len(pairs)==54 and len(firmware['comparison']['right_only'])==4 and not firmware['comparison']['left_only']
    changed={k:sum(not r[k] for r in pairs) for k in pairs[0] if k.endswith('_same')}
    assert changed=={'size_same':4,'flags_same':0,'destination_field_same':48,'directory_digest_same':17,'tail_candidate_16_same':40,'raw_sha256_same':40}
    diff=load(RESULTS/'oss_selected_diff.json')
    assert len(diff['pairs'])==5 and len(diff['other_historical_renamed_pairs_not_content_reviewed'])==3
    assert all(r['bytes_equal_after_literal_MC8223_to_MC8223X_replacement'] for r in diff['pairs'])
    oss=load(RESULTS/'oss_boundary.json')
    assert len(oss['archives'])==6 and len(oss['function_index'])==28
    android=load(RESULTS/'android_method_index.json')
    assert len(android['methods'])==81
    control=load(RESULTS/'synthetic_controls.json')
    assert control['normal_reassembled_equal']
    short=control['captured_length_21_actual_length_17_last_chunk']
    assert (short['actual_read'],short['request_body_length'],short['body_hex'])==(1,5,'1100000000')
    # Independently check every published instruction excerpt against its raw DEX.
    rechecked=0;excerpt_instructions=0
    if a.with_inputs:
        cfg=config();source=Path(cfg['source_root'])
        for row in inputs['inputs']:
            kind=row['kind']
            if kind=='firmware_ZIP':
                path=Path(cfg['firmware'][row['label']]);actual=file_id(path)
            elif kind=='firmware_BIN_member':
                with zipfile.ZipFile(cfg['firmware'][row['label']]) as z:
                    b=z.read(row['member']);actual={'size':len(b),'sha256':digest(b)}
            elif kind=='official_OSS_archive':
                actual=file_id(Path(cfg['oss_root'])/row['name'])
            elif kind=='APK':
                actual=file_id(Path(row['path_token'].replace('<SOURCE_ROOT>',str(source))))
            elif kind=='DEX':
                actual=file_id(source/'extracted/base'/row['member'])
            else:
                actual=file_id(source/'extracted/arm64'/row['member'])
            assert actual=={k:row[k] for k in ('size','sha256')},row
            rechecked+=1
        raw={n:(source/'extracted/base'/n).read_bytes() for n in ('classes.dex','classes2.dex')}
        evidence=load(RESULTS/'android_instruction_evidence.json')
        for excerpt in evidence['excerpts']:
            for ins in excerpt['instructions']:
                at=ins['file_offset'];end=at+2*ins['width_cu']
                assert raw[excerpt['dex']][at:end].hex()==ins['raw_hex']
                excerpt_instructions+=1
    result={'status':'PASS','public_metadata_cross_checks':True,'input_identities_rechecked':rechecked,
            'raw_excerpt_instructions_byte_compared':excerpt_instructions,
            'two_version_comparison_changed_field_counts':changed,
            'scope':'Cross-check only. No new scan/decompilation, target execution, device request or input modification.'}
    if a.record:save(RESULTS/'final_validation.json',result)
    print(result)

if __name__=='__main__':
    main()
