"""Follow only four magic-identified nested assets from stage A; no active rules run."""
import io
import gzip
import struct
import zipfile
from common import *
def main():
    results=[]
    with zipfile.ZipFile(SOURCE/'apk/com.panasonic.jp.lumixlab-22.apk') as apk:
        for name in ('assets/zip/rules-broadcast.zip','assets/zip/rules-localNotification.zip','assets/zip/rules-personalized.zip'):
            b=apk.read(name);members=[]
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                for info in z.infolist():
                    data=z.read(info);keys=None
                    try:
                        value=json.loads(data);keys=list(value) if isinstance(value,dict) else {'json_type':type(value).__name__,'length':len(value) if hasattr(value,'__len__') else None}
                    except (ValueError,UnicodeDecodeError):pass
                    members.append({'path':info.filename,'size':len(data),'sha256':sha(data),'crc32':f'{info.CRC:08x}','json_root_keys_or_type':keys})
            results.append({'apk_member':name,'sha256':sha(b),'nested_members':members,'all_member_CRC_pass':True})
        name='okhttp3/internal/publicsuffix/publicsuffixes.gz';b=apk.read(name);data=gzip.decompress(b);pos=0;sections=[]
        for i in range(2):
            n=struct.unpack_from('>I',data,pos)[0];pos+=4;part=data[pos:pos+n];pos+=n
            assert len(part)==n;part.decode('utf-8')
            sections.append({'index':i,'size':n,'sha256':sha(part),'newline_count':part.count(b'\n')})
        assert pos==len(data)
        results.append({'apk_member':name,'compressed_sha256':sha(b),'decoded_size':len(data),'decoded_sha256':sha(data),
                        'observed_format':'two big-endian u32 length-prefixed UTF-8 byte sections; entire decoded range consumed','sections':sections})
    save(RESULTS/'nested_assets.json',{'objects':results,'scope':'Only four observed magic positives; no JavaScript/rule evaluation, no nested executable run, no entropy-based encryption claims.'})
    print('PASS: 3 nested ZIP CRC/hash inventories + one gzip/two-length-section parser')
if __name__=='__main__':main()
