"""Query inherited indexes: API references are not semantic/runtime-use proofs."""
import collections,re
from common import *
PATTERNS={
 'java_crypto':('Ljavax/crypto/',),
 'java_security':('Ljava/security/',),
 'android_keystore':('Landroid/security/keystore/','Landroid/security/KeyPairGeneratorSpec'),
 'tls':('Ljavax/net/ssl/',),
 'compression_crc':('Ljava/util/zip/',),
 'base64':('Landroid/util/Base64','Ljava/util/Base64'),
 'url_encoding':('Ljava/net/URLEncoder;','Ljava/net/URLDecoder;'),
 'object_serialization':('Ljava/io/ObjectInputStream;','Ljava/io/ObjectOutputStream;'),
 'json':('Lorg/json/','Lcom/google/gson/Gson;','Lcom/google/gson/stream/','Landroid/util/JsonReader;','Landroid/util/JsonWriter;'),
 'parcel_serialization':('Landroid/os/Parcel;',),
 'bytebuffer_conversion':('Ljava/nio/ByteBuffer;','Ljava/nio/ByteOrder;'),
 'protobuf_declared':('Lcom/google/protobuf/','Lcom/google/crypto/tink/shaded/protobuf/'),
}
ALG=re.compile(r'(?:AES(?:/[A-Za-z0-9-]+/[A-Za-z0-9-]+)?|RSA(?:/[A-Za-z0-9-]+/[A-Za-z0-9-]+)?|EC|ECDH|DH|SHA-?[0-9]+|MD5|Hmac\w+|AndroidKeyStore|PKCS12|JKS|X\.509|SHA[0-9]+withRSA|SHA[0-9]+withECDSA)',re.I)
NATIVE=re.compile(r'(^|_)(?:AES|RSA|EC|ECDH|ECDSA|EVP|HMAC|SHA[0-9]*|MD5|SSL|TLS|CRYPTO|inflate|deflate|crc32|adler32|compress|uncompress|BIO|PEM|X509)(?:_|$)',re.I)
def main():
    WORK.mkdir(parents=True,exist_ok=True)
    ms=methods();assert len(ms)==76901 and sum(len(m['calls']) for m in ms)==349415
    callers=collections.defaultdict(list)
    for m in ms:
        for c in m['calls']:callers[c['reference']].append({'method':m['method'],'dex':m['dex'],'cu':c['offset_cu']})
    sites=[];candidate_methods=set()
    for m in ms:
        for c in m['calls']:
            groups=[g for g,ps in PATTERNS.items() if c['reference'].startswith(ps)]
            if groups:
                sites.append({'method':m['method'],'dex':m['dex'],'cu':c['offset_cu'],'target':c['reference'],
                              'categories':groups,'namespace':namespace(m['method'])})
                candidate_methods.add(m['method'])
    summary=collections.Counter(g for s in sites for g in s['categories'])
    # Declared algorithm labels are safe constants, not keys/aliases/certificates.
    algs=[{'method':m['method'],'dex':m['dex'],'labels':[{'cu':s['offset_cu'],'value':s['value']} for s in m['strings'] if ALG.fullmatch(s['value'])],
           'explicit_callers':callers[m['method']]} for m in ms if any(ALG.fullmatch(s['value']) for s in m['strings'])]
    save(RESULTS/'api_usage.json.gz',{'patterns':PATTERNS,'sites':sites,'scope':'All inherited 76901 method bodies and 349415 explicit invoke references. Exceptions/providers/constructors included; pure Java/custom native algorithms outside prefix rules remain candidates, not absence. Virtual runtime use not proved.'},True)
    save(RESULTS/'algorithm_labels.json.gz',{'allowlist_regex':ALG.pattern,'methods':algs,'meaning':'Observed labels only; parameter/caller confirmation required. No key/alias/certificate material published.'},True)
    dynamic=load(PREV/'results/dispatch_sites.json.gz')['dynamic_reflection_load_sites']
    assert len(dynamic)==243
    save(RESULTS/'dynamic_seed.json',{'candidates':dynamic,'count':243})
    native=[]
    for lib in load(PREV/'results/elf_structure.json.gz')['libraries']:
        syms=[s for s in lib['symbols'] if NATIVE.search(s['name'])]
        native.append({'library':lib['library'],'sha256':lib['sha256'],'needed':lib['needed'],'matching_symbols':syms,
                       'status':'symbol/import candidate only; no semantic or runtime-use claim'})
    save(RESULTS/'native_api_candidates.json.gz',{'pattern':NATIVE.pattern,'libraries':native},True)
    # Dump only 243-site caller bodies + API consumers, not all 76901 methods again.
    selected={d['caller'] for d in dynamic}|candidate_methods
    selected|={m['method'] for m in ms if m['method'].startswith(('Lcom/panasonic/jp/lumixlab/bean/RawProcessingConfigBean;','Lh6/d;','Lcom/google/android/gms/tasks/NativeOnCompleteListener;','Lcom/panasonic/jp/lumixlab/LlcApplication;'))}
    with (WORK/'targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(sorted(selected))+'\n')
    save(RESULTS/'inventory_summary.json',{'methods':len(ms),'invokes':349415,'api_sites':len(sites),'api_methods':len(candidate_methods),'category_counts':dict(summary),'algorithm_label_methods':len(algs),
         'dynamic_candidates':243,'selected_method_dumps':len(selected),'ownership_rule':'Namespace is declaration evidence only. Obfuscated SDK attribution requires consumers/source metadata.'})
    print('Queried inherited index:',len(sites),'API sites;',len(selected),'selected bodies;',dict(summary))
if __name__=='__main__':main()
