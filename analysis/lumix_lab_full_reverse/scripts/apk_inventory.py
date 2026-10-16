"""Read all original APK members, hash and identify only concrete magic bytes."""
import collections
import struct
import zipfile
from common import *

def main():
    old=load(ROOT/'analysis/lab_stage1_20261015/results/inputs.json')['input_files']
    inputs=[]
    for row in old:
        if row['kind']=='APK':p=Path(row['path_token'].replace('<SOURCE_ROOT>',str(SOURCE)))
        elif row['kind']=='DEX':p=SOURCE/'extracted/base'/row['member']
        else:p=SOURCE/'extracted/arm64'/row['member']
        assert file_id(p)=={k:row[k] for k in ('size','sha256')}
        inputs.append(row)
    reports=[]
    for row in inputs:
        if row['kind']!='APK':continue
        p=Path(row['path_token'].replace('<SOURCE_ROOT>',str(SOURCE)))
        members=[];seen=set()
        with zipfile.ZipFile(p) as z:
            for m in z.infolist():
                assert m.filename not in seen;seen.add(m.filename)
                b=z.read(m) # Full member and CRC, no extraction or execution.
                assert len(b)==m.file_size
                fmt=[]
                for prefix,label in ((b'PK\x03\x04','ZIP'),(b'\x1f\x8b','gzip'),(b'\x7fELF','ELF'),(b'dex\n','DEX'),(b'\x89PNG\r\n\x1a\n','PNG'),(b'\xff\xd8\xff','JPEG')):
                    if b.startswith(prefix):fmt.append(label)
                if len(b)>=8 and b[:2] in (b'\x03\x00',b'\x02\x00'):
                    typ,hdr,total=struct.unpack_from('<HHI',b)
                    if total==len(b) and 8<=hdr<=total:fmt.append('Android_resource_chunk_'+hex(typ))
                members.append({'path':m.filename,'size':len(b),'compressed_size':m.compress_size,
                                'method':m.compress_type,'flags':m.flag_bits,'crc32':f'{m.CRC:08x}',
                                'sha256':sha(b),'header_magic_matches':fmt,
                                'top_directory':m.filename.split('/')[0] if '/' in m.filename else '<root>'})
        reports.append({'apk':p.name,**file_id(p),'member_count':len(members),
                        'top_directory_counts':dict(collections.Counter(r['top_directory'] for r in members)),
                        'members':members})
    save(RESULTS/'input_manifest.json',{'version':'3.1.0 versionCode 22','inputs':inputs,'all_25_rechecked':True,
         'boundary':'Existing delivery lineage retained; no new publisher signature trust validation.'})
    save(RESULTS/'apk_members.json.gz',{'apks':reports,'method':'full ZipFile member read/hash/CRC; magic is format evidence only'},True)
    save(RESULTS/'apk_summary.json',{'apks':[{k:v for k,v in r.items() if k!='members'} for r in reports],
         'embedded_format_candidates':[{'apk':r['apk'],**m} for r in reports for m in r['members']
             if any(f in ('ZIP','gzip','ELF','DEX') for f in m['header_magic_matches'])],
         'all_member_count':sum(len(r['members']) for r in reports)})
    print('PASS 25 original inputs;',sum(len(r['members']) for r in reports),'APK members fully hashed/CRC checked')

if __name__=='__main__':main()
