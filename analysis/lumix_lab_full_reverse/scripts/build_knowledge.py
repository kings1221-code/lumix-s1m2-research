"""Build metadata knowledge base from prior invoke index plus new class/resource data.
No decompilation repeat; raw strings/values and original source remain local.
"""
import collections
import re
import sqlite3
import struct
import xml.etree.ElementTree as ET
from common import *

A='{http://schemas.android.com/apk/res/android}'
def attrs(e):return {k.removeprefix(A):v for k,v in e.attrib.items()}
def pkg(name):return name.lstrip('L').split(';')[0].rsplit('/',1)[0].replace('/','.') if '/' in name else '<default>'

def main():
    methods=jsonl(ROOT/'.research-local/stage1/dex_index_v2.jsonl')
    classes=jsonl(WORK/'dex_classes.jsonl')
    assert len(methods)==76901 and len(classes)==14812
    classmap={r['class']:r for r in classes}
    manifests=[];resources=[];navigation=[]
    for root in sorted((WORK/'apktool').iterdir()):
        doc=ET.parse(root/'AndroidManifest.xml').getroot();app=doc.find('application')
        components=[]
        if app is not None:
            for e in app:
                if e.tag in ('activity','activity-alias','service','receiver','provider'):
                    name=e.get(A+'name','');d='L'+name.replace('.','/')+';'
                    components.append({'type':e.tag,'attributes':attrs(e),'class_defined_in_DEX':d in classmap,
                        'intent_filters': [{'actions':[attrs(x) for x in q.findall('action')],
                                            'categories':[attrs(x) for x in q.findall('category')],
                                            'data':[attrs(x) for x in q.findall('data')]} for q in e.findall('intent-filter')]})
        manifests.append({'split':root.name,'decoded_manifest_id':file_id(root/'AndroidManifest.xml'),
                          'attributes':attrs(doc),'application':attrs(app) if app is not None else None,
                          'permissions':[attrs(e) for e in doc if e.tag in ('uses-permission','permission')],
                          'components':components})
        public=root/'res/values/public.xml'
        if public.exists():
            for r in ET.parse(public).getroot():resources.append({'split':root.name,**r.attrib})
        for nav in (root/'res').glob('navigation*/*.xml'):
            for e in ET.parse(nav).iter():
                if e.tag in ('fragment','activity','dialog','navigation'):
                    navigation.append({'split':root.name,'file':nav.relative_to(root).as_posix(),'type':e.tag,'attributes':attrs(e)})
    save(RESULTS/'android_components.json',{'manifests':manifests,'navigation':navigation,
        'limits':'Manifest declarations/exported attributes and navigation are not runtime reachability or permission enforcement proofs.'})
    save(RESULTS/'resource_ids.json.gz',{'resources':resources},True)
    # Public structural index omits method string constants and field values.
    mids={r['method']:i for i,r in enumerate(methods)}
    definitions=[{'id':i,**{k:r[k] for k in ('dex','method','access_flags','native','code_units')}} for i,r in enumerate(methods)]
    refs=sorted({c['reference'] for r in methods for c in r['calls']});rid={s:i for i,s in enumerate(refs)}
    edges=[[i,c['offset_cu'],rid[c['reference']],c['opcode']] for i,r in enumerate(methods) for c in r['calls']]
    save(RESULTS/'dex_structure.json.gz',{'classes':classes,'methods':definitions,'call_targets':refs,'invoke_edges':edges,
        'meaning':'Encoded invoke references only; virtual/interface target references are not resolved runtime dispatch.'},True)
    # Local query database does not copy string constants or proprietary executable bytes.
    db=sqlite3.connect(WORK/'knowledge.sqlite');db.executescript('CREATE TABLE methods(id INTEGER PRIMARY KEY, descriptor TEXT UNIQUE, dex TEXT, flags INT, cu INT); CREATE TABLE calls(caller INT, cu INT, target TEXT, opcode TEXT); CREATE INDEX target_idx ON calls(target); CREATE INDEX caller_idx ON calls(caller);')
    db.executemany('INSERT INTO methods VALUES(?,?,?,?,?)',[(i,r['method'],r['dex'],r['access_flags'],r['code_units']) for i,r in enumerate(methods)])
    db.executemany('INSERT INTO calls VALUES(?,?,?,?)',[(i,c['offset_cu'],c['reference'],c['opcode']) for i,r in enumerate(methods) for c in r['calls']]);db.commit();db.close()
    graph=collections.Counter((pkg(r['method'].split('->')[0]),pkg(c['reference'].split('->')[0])) for r in methods for c in r['calls'])
    save(RESULTS/'package_graph.json.gz',{'edges':[{'caller_package':a,'target_package':b,'sites':n} for (a,b),n in sorted(graph.items())],
        'namespace_limits':'com.panasonic namespace is a verified namespace, not proof all other obfuscated namespaces are third-party.'},True)
    dynamic=[];async_calls=[]
    for r in methods:
        for c in r['calls']:
            ref=c['reference']
            row={'caller':r['method'],'dex':r['dex'],'offset_cu':c['offset_cu'],'target':ref}
            if any(t in ref for t in ('DexClassLoader;','PathClassLoader;','InMemoryDexClassLoader;','Class;->forName(', 'ClassLoader;->loadClass(', 'Method;->invoke(', 'System;->load')):dynamic.append(row)
            if any(t in ref for t in ('Executor;->execute(', 'ExecutorService;->submit(', 'Handler;->post(', 'Thread;->start(', 'Task;->addOnCompleteListener(', 'Continuation;->resumeWith(', 'LiveData;->observe(')):async_calls.append(row)
    save(RESULTS/'dispatch_sites.json.gz',{'dynamic_reflection_load_sites':dynamic,'async_sites':async_calls,
        'limits':'Candidates from exact invoke references in all saved methods; not every callback, Rx/coroutine or computed dispatch resolved.'},True)
    # All raw DEX string table entries indexed by ID/hash; plaintext stays local.
    strings=[]
    for name in ('classes.dex','classes2.dex'):
        b=(SOURCE/'extracted/base'/name).read_bytes();n,at=struct.unpack_from('<II',b,56)
        for i in range(n):
            off=struct.unpack_from('<I',b,at+4*i)[0];pos=off;length=0;shift=0
            while True:
                x=b[pos];pos+=1;length|=(x&127)<<shift
                if x<128:break
                shift+=7
            end=b.index(0,pos);raw=b[pos:end]
            strings.append({'dex':name,'string_id':i,'data_offset':off,'utf16_length':length,'raw_mutf8_sha256':sha(raw)})
    save(RESULTS/'dex_strings.json.gz',{'strings':strings,'plaintext_policy':'No raw constant values published; important strings are cited only after semantic review/redaction.'},True)
    save(RESULTS/'dex_summary.json',{'classes':len(classes),'fields':sum(len(c['fields']) for c in classes),'method_definitions':len(methods),
         'call_targets':len(refs),'invoke_sites':len(edges),'strings':len(strings),'resource_ids':len(resources),
         'components':dict(collections.Counter(c['type'] for m in manifests for c in m['components'])),
         'navigation_nodes':len(navigation),'dynamic_reflection_load_sites':len(dynamic),'selected_async_sites':len(async_calls),
         'namespace_class_counts':dict(collections.Counter('panasonic_namespace' if c['class'].startswith('Lcom/panasonic/') else 'other_namespace_not_ownership_proof' for c in classes)),
         'local_query_database_id':file_id(WORK/'knowledge.sqlite')})
    print('Indexed',len(classes),'classes,',len(methods),'methods,',len(edges),'invoke sites; no method scan repeated')

if __name__=='__main__':main()
