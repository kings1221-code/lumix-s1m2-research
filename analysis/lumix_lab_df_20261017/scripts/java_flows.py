"""Reviewed bounded consumers + original-code evidence links; no credential values."""
import collections,re
from common import *
from dynamic import flow
from inventory import ALG
SPECS=[
 ('camera_peer_fingerprint','Lh6/d;->verify(',['getPeerCertificates','getEncoded','MessageDigest;->update','MessageDigest;->isEqual'],
  'SSLSession peer certificate encoded bytes; expected digest from app connection state','SHA-256, certificate[0]; two selector branches','boolean equality result consumed by HostnameVerifier','Camera HTTPS certificate fingerprint, inherited and reinforced; NOT firmware-file verification'),
 ('filename_uint32','Lcom/panasonic/jp/lumixlab/bean/RawProcessingConfigBean;->hashFileNameToUint32(',['MessageDigest;->digest','String;->getBytes','Math;->min'],
  'String method parameter, default charset','SHA-256 first min(4,digest.length) bytes, big-endian integer fold','returns int; no explicit DEX caller in this input','Implementation present; actual App use unconfirmed'),
 ('lottie_cache_filename','LI2/f;->a(',['replaceAll','MessageDigest;->digest','String;->format'],
  'cache-key string and extension/temp flag','Only over-length normalized name uses MD5; hexadecimal formatting','lottie_cache_ filename; I2/f cache lookup/write helpers','Lottie cache naming, not payload authentication'),
 ('image_disk_cache_key','LT2/u;->a(',['LP2/q;->b','MessageDigest;->digest'],
  'P2/q cache-key update interface; digest object from pool','Digest consumer; SHA-256 factory is LT2/s.create','hexadecimal safe cache key string stored in lookup cache','Glide-associated cache chain; interface target details remain polymorphic'),
 ('firebase_legacy_installation_id','LR4/d;->a(',['SharedPreferences;->getString','KeyFactory;->generatePublic','MessageDigest;->digest','Base64;->encodeToString'],
  'SDK SharedPreferences public-key representation (not read at runtime)','Base64 decode -> RSA X509 public-key parse -> SHA1(encoded key), modified first byte, first 8 bytes Base64 flags11','returns legacy installation identifier to SDK callers','Public-key decoding/hashing, NOT RSA encryption or firmware signature validation'),
 ('play_review_store_identity','Lq4/k;-><init>(',['PackageManager;->getPackageInfo','Signature;->toByteArray','MessageDigest;->digest','Intent;->setPackage'],
  'com.android.vending package signatures obtained from PackageManager','SHA-256 -> Base64 flags11 -> equality checks; stored comparison constants redacted','conditional construction of Play in-app-review binding client','SDK store identity check, not camera/firmware verification'),
 ('firebase_app_name_hash','Lcom/google/firebase/messaging/GmsRpc;->getHashedFirebaseAppName(',['MessageDigest;->digest','GmsRpc;->base64UrlSafe'],
  'Firebase app name string','SHA-1 digest and Base64 encoding','SDK registration/request metadata string','SDK identifier derivation; no firmware byte input'),
 ('adobe_string_hash','Lcom/adobe/marketing/mobile/internal/util/i;->a(',['MessageDigest;->update','MessageDigest;->digest'],
  'String method parameter, encoding selected in original code','SHA-256 -> hexadecimal string construction','returns to Adobe SDK callers','Hash helper dataflow verified; real runtime data/identity meaning not asserted'),
 ('oauth_hmac_sha256','Lcom/google/api/client/auth/oauth/OAuthHmacSha256Signer;->computeSignature(',['SecretKeySpec;-><init>','Mac;->getInstance','Mac;->init','Mac;->doFinal'],
  'signature-base string parameter and secret fields supplied by caller','HmacSHA256; key composed from URL-encoded secret inputs; runtime secrets not obtained','SDK BaseEncoding wrapper consumer; encoder alphabet not independently restored here','SDK implementation present; selected App authorization flow not established'),
 ('oauth_hmac_sha1','Lcom/google/api/client/auth/oauth/OAuthHmacSigner;->computeSignature(',['SecretKeySpec;-><init>','Mac;->init','Mac;->doFinal'],
  'signature-base string parameter and secret fields supplied by caller','HmacSHA1; runtime key material not obtained','SDK Base64 wrapper consumer; encoder internals not independently restored here','SDK implementation present; not an App firmware algorithm'),
 ('pkce_challenge','Lcom/google/api/client/auth/oauth2/AuthorizationCodeFlow$PKCE;->generateChallenge(',['MessageDigest;->update','MessageDigest;->digest','encodeBase64URLSafeString'],
  'code-verifier String parameter','SHA-256 -> Base64 URL-safe','challenge field set by OAuth SDK','Static transformation verified; App selection of this SDK option unconfirmed'),
 ('community_zip','Lcom/panasonic/jp/lumixlab/controller/fragment/CommunityDownloadFragment;->o0(',['ZipInputStream;->getNextEntry','ZipEntry;->getName','ZipEntry;->isDirectory'],
  'downloaded/local file passed to community callback','ZIP entry selection and file handling; no crypto API in this method','community download/extraction consumers','ZIP use exists outside firmware; full malformed/path-safety behavior not restored'),
 ('http_basic_encoding','Lh6/h;->j(',['Base64;->decode','LI5/d;->a','Base64;->encodeToString','Lh6/c;-><init>'],
  'embedded encoded strings (values not decoded/exported) -> byte/character helper -> colon concatenation','Base64 decoding and encoding, flags0/2; not encryption','h6/c interceptor -> HTTP Authorization header','Static header construction only; no service contacted or authentication tested'),
 ('printable_ascii_filter','LI5/d;->a(',['StringBuilder;->append(C)','StringBuilder;->toString'],
  'byte[] method parameter','Stop on first NUL; retain only signed-byte values 33..126, append as char','String return used by h6/h.j and util/t0.b before header encoding','Filtering conversion, not a general UTF-8 decoder or cryptographic transform'),
]
def main():
    ms=methods();callers=collections.defaultdict(list)
    for m in ms:
        for c in m['calls']:callers[c['reference']].append({'caller':m['method'],'dex':m['dex'],'cu':c['offset_cu']})
    raw={m['method']:m for m in rows(WORK/'instructions.jsonl')+rows(WORK/'extra_instructions.jsonl')}
    evidence={m['method']:m for m in load(RESULTS/'selected_dex_evidence.json.gz')['methods']}
    facts=[]
    for label,prefix,need,input_,parameters,output,meaning in SPECS:
        selected=[m for m in raw.values() if m['method'].startswith(prefix)];assert len(selected)==1,(prefix,len(selected))
        m=selected[0];refs=[c['reference'] for c in m['calls']]
        for s in need:assert any(s in r for r in refs),(label,s)
        facts.append({'id':label,'method':m['method'],'evidence':evidence[m['method']],'explicit_callers':callers[m['method']],
                      'input':input_,'parameters':parameters,'output_consumer':output,'interpretation':meaning,
                      'supporting_calls':[{'cu':c['offset_cu'],'target':c['reference']} for c in m['calls']],
                      'status':'verified bounded static consumer; runtime execution not tested'})
    save(RESULTS/'java_dataflows.json',{'flows':facts,'validation':'Each reviewed flow links original method SHA/code_item, independent invoke target/register checks, exact callees and upstream caller references. Input semantics reviewed against selected raw DEX; no original application execution or secret-value extraction.'})
    factories=[]
    for m in raw.values():
        calls=[c for c in m['calls'] if '->getInstance(' in c['reference'] and c['reference'].startswith(('Ljava/security/','Ljavax/crypto/','Ljavax/net/ssl/'))]
        if not calls:continue
        states=flow(m)
        for c in calls:
            i=next(i for i in m['instructions'] if i['offset_cu']==c['offset_cu']);s=states.get(c['offset_cu'],{});args=[]
            for r in i['registers']:
                v=s.get(r)
                if v and v[0]=='str':
                    value=v[1] if ALG.fullmatch(v[1]) or v[1] in ('TLS','TLSv1.2','TLSv1.3','AndroidCAStore','BKS','BC','BCJSSE') else '<non-allowlisted constant redacted>'
                    args.append({'kind':'literal','label':value})
                else:args.append({'kind':'unresolved or runtime/provider value'})
            factories.append({'method':m['method'],'dex':m['dex'],'cu':c['offset_cu'],'target':c['reference'],'arguments':args,'namespace':namespace(m['method'])})
    save(RESULTS/'java_factory_parameters.json',{'sites':factories,'limits':'Original CFG local constant facts only. Wrapper/interface/provider parameters not fabricated; algorithm label recovery is not runtime selection proof.'})
    android_calls=[{'method':m['method'],'target':c['reference'],'cu':c['offset_cu']} for m in ms for c in m['calls'] if c['reference'].startswith(('Landroid/security/keystore/','Landroid/security/KeyPairGeneratorSpec'))]
    labels=[{'method':m['method'],'cu':s['offset_cu']} for m in ms for s in m['strings'] if s['value']=='AndroidKeyStore']
    pan=[{'method':m['method'],'target':c['reference'],'cu':c['offset_cu']} for m in ms if m['method'].startswith('Lcom/panasonic/') for c in m['calls'] if c['reference'].startswith(('Ljavax/crypto/','Ljava/security/Signature;','Ljava/security/MessageDigest;'))]
    save(RESULTS/'java_negative_scope.json',{'android_keystore_direct_type_sites':android_calls,'AndroidKeyStore_literal_consumers':labels,
          'Panasonic_namespace_direct_crypto_digest_signature_sites':pan,
          'scope':'All saved 76901 methods and their 349415 invokes/string operands from exact two DEX. No absence claim for reflected providers, obfuscated first-party packages, pure implementations, external modules or runtime code.'})
    helper=raw['LI5/d;->a([B)Ljava/lang/String;'];ins={i['offset_cu']:i for i in helper['instructions']}
    assert ins[14]['literal']==33 and ins[18]['literal']==126 and ins[11]['opcode']=='if-nez' and ins[13]['target_cu']==30
    synthetic=bytes((32,33,65,126,127,255,0,66));loop=[]
    for v in synthetic:
        if v==0:break
        if 33<=v<=126:loop.append(chr(v))
    independent=bytes(v for v in synthetic.split(b'\0',1)[0] if 33<=v<=126).decode('ascii')
    assert ''.join(loop)==independent=='!A~'
    save(RESULTS/'ascii_filter_control.json',{'status':'PASS','input_hex':synthetic.hex(),'output':independent,
         'original_method':helper['method'],'limit':'Self-written loop/model control plus DEX branch/constant checks. No embedded credential bytes decoded or used; no target method execution.'})
    print('PASS:',len(facts),'reviewed Java consumers;',len(factories),'factory parameter sites; Android Keystore type sites',len(android_calls))
if __name__=='__main__':main()
