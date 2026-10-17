"""Query 73540 inherited string IDs by allowlisted label hashes; never dump secrets."""
import collections
from common import *
from inventory import ALG
def main():
    ms=methods();labels={s['value'] for m in ms for s in m['strings'] if ALG.fullmatch(s['value'])}
    labels|={'AES','AES/CBC/PKCS5Padding','AES/GCM/NoPadding','RSA/ECB/PKCS1Padding','AndroidKeyStore','TLS','TLSv1.2','TLSv1.3'}
    hashes={sha(s.encode('ascii')):s for s in labels};table=load(PREV/'results/dex_strings.json.gz')['strings'];assert len(table)==73540
    blobs={name:(SOURCE/'extracted/base'/name).read_bytes() for name in ('classes.dex','classes2.dex')};matched=[]
    for r in table:
        if r['raw_mutf8_sha256'] not in hashes:continue
        label=hashes[r['raw_mutf8_sha256']];b=blobs[r['dex']];at=r['data_offset']
        while b[at]&128:at+=1
        at+=1;end=b.index(0,at);assert b[at:end]==label.encode('ascii')
        matched.append({**r,'allowlisted_label':label,'explicit_method_constant_sites':[{'method':m['method'],'cu':s['offset_cu']} for m in ms for s in m['strings'] if m['dex']==r['dex'] and s['value']==label]})
    supplemental=[{'method':m['method'],'dex':m['dex'],'cu':c['offset_cu'],'target':c['reference']} for m in ms for c in m['calls'] if c['reference'].startswith(('LI5/d;','Lw4/h;'))]
    save(RESULTS/'string_label_crosscheck.json',{'string_ID_denominator':73540,'label_allowlist':sorted(labels),'matched_IDs':matched,
       'supplemental_encoding_references':supplemental,
       'scope':'Hash lookup on prior full string-ID table and targeted original MUTF8 byte verification; labels are candidates, never proof of input/algorithm/runtime use. Supplement covers known byte/ASCII/hex and SDK BaseEncoding helpers; arbitrary custom encoders remain outside API-prefix completeness.'})
    print('PASS',len(matched),'allowlisted string IDs original-byte checked;',len(supplemental),'supplemental encoding references')
if __name__=='__main__':main()
