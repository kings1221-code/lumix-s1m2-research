"""Assemble input/provenance ledger from actual checks, retaining evidence levels."""
import sys
from common import ROOT, WORK, RESULTS, load, save, file_id

def main():
    p=load(RESULTS/'stage1_preservation.json')
    f=load(RESULTS/'firmware_structure.json')
    o=load(RESULTS/'oss_boundary.json')
    pages=load(RESULTS/'official_pages.json')
    old31=load(ROOT/'analysis/sources/lumix_sync_static/official_firmware_list/S5M2_full_inventory.json')
    acquisition=load(ROOT/'downloads/provenance/objects/s5m2-firmware-current.json')
    assert f['images']['S5M2_V31']['zip']['asset']=={'size':old31['zip_bytes'],'sha256':old31['zip_sha256']}
    assert f['images']['S5M2_V37']['zip']['asset']=={'size':acquisition['size'],'sha256':acquisition['hashes']['sha256']}
    inputs=[{**r,'stage2_status':'actual_local_file_SHA256_rechecked; stage1 lineage retained'} for r in p['input_files_rechecked']]
    for label,image in f['images'].items():
        if label=='S5M2_V31':
            url=old31['url'];status='historical_official_URL_and_ZIP_hash_record_matched; no fresh download attestation'
        else:
            url=acquisition['final_url'];status='saved_2026-10-15_official_HTTP_download_record_and_current_official_filename_matched'
            assert 'S5m2_V37.zip' in (WORK/'official_pages/firmware_release.html').read_text(encoding='utf-8')
        inputs.append({'kind':'firmware_ZIP','label':label,**image['zip']['asset'],
                       'source_url':url,'source_status':status,'local_status':'actual ZIP read-only; all member CRCs passed',
                       'binary_published':False})
        inputs.append({'kind':'firmware_BIN_member','label':label,'member':image['zip']['members'][0]['name'],
                       'size':image['bytes'],'sha256':image['sha256'],'container_sha256':image['zip']['asset']['sha256'],
                       'source_status':status,'local_status':'decompressed in memory only; complete BIN hash and actual directory checks passed',
                       'binary_published':False})
    for filename,r in o['archives'].items():
        page=next(p for p in pages['pages'] if p['label']==('oss_ver1' if 'Ver1' in filename else 'oss_ver2'))
        assert r['official_url'] in page['relevant_links']
        inputs.append({'kind':'official_OSS_archive','name':filename,**r['archive'],'source_url':r['official_url'],
                       'source_status':'current official page link + whole archive hash matches earlier official acquisition audit',
                       'source_model_label':r['source_model_label'],'local_status':'whole archive SHA256 + selected source spans rechecked',
                       'archive_published':False})
    save(RESULTS/'inputs.json',{'inputs':inputs,'input_identity_count':len(inputs),
         'note':'All SHA-256 values are local measurements/research reference values, not manufacturer-signed checksums.',
         'historical_corpus_other_versions':'8 other identities retained only in pinned corpus/profile history; not reanalyzed or promoted to current verification.',
         'missing':[{'item':'S5M2 HTTPS firmware endpoint receiver / proprietary update dispatcher','needed':'lawfully held same-model binary/source with version, hash and deployment context'},
                    {'item':'modern UPD authentication/decode consumer','needed':'readable code that demonstrably reads actual UPD fields and payload bytes'},
                    {'item':'actual deployed S5M2 DTB, rootfs/init/service configuration and flash/RAM mapping','needed':'version-linked original files or existing lawful captures; no live acquisition performed'}],
         'historical_records':{'v31_reference':{'path':'analysis/sources/lumix_sync_static/official_firmware_list/S5M2_full_inventory.json',**file_id(ROOT/'analysis/sources/lumix_sync_static/official_firmware_list/S5M2_full_inventory.json')},
                               'v37_http_record':{'path':'downloads/provenance/objects/s5m2-firmware-current.json',**file_id(ROOT/'downloads/provenance/objects/s5m2-firmware-current.json'),
                                                  'started_utc':acquisition['started_utc'],'completed_utc':acquisition['completed_utc'],'url':acquisition['final_url']}}})
    save(RESULTS/'environment.json',{'python':sys.version,'new_dependencies_installed':[],
         'analysis_tools_used':['Python standard library','official Temurin JDK 25.0.4.1+1','official JADX 1.5.6 bundled dexlib2 and Gson'],
         'stage1_tools_reference':{'path':'analysis/lab_stage1_20261015/results/tools.json',**file_id(ROOT/'analysis/lab_stage1_20261015/results/tools.json')},
         'ghidra_reanalysis':False,'target_APK_DEX_SO_firmware_execution':False,'camera_IO':False})
    print('PASS: input ledger',len(inputs),'identities; provenance tiers retained; no binary publication')

if __name__=='__main__':
    main()
