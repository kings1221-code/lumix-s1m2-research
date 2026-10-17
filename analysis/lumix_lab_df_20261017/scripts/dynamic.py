"""Conservative literal propagation through actual DEX CFG for 243 saved candidates."""
import collections,re
from common import *
def successors(m):
    ins=m['instructions'];by={i['offset_cu']:i for i in ins};out={}
    for i in ins:
        at=i['offset_cu'];op=i['opcode'];n=at+i['width_cu'];to=[]
        if 'payload' in op:out[at]=[];continue
        if op.startswith('goto'):to=[i['target_cu']]
        elif op.startswith(('return','throw')):to=[]
        elif op.startswith('if-'):to=[n,i['target_cu']]
        elif op in ('packed-switch','sparse-switch'):
            to=[n]+[at+e['relative_target_cu'] for e in by[i['target_cu']]['switch_elements']]
        elif n in by:to=[n]
        out[at]=[(v,False) for v in to if v in by]
        for tr in m.get('try_blocks',[]):
            if tr['start_cu']<=at<tr['start_cu']+tr['count_cu']:
                out[at]+=[(h['target_cu'],True) for h in tr['handlers']]
    return out
def flow(m):
    ins={i['offset_cu']:i for i in m['instructions']}
    if not ins:return {}
    edges=successors(m);states={0:{}};queue=collections.deque([0]);queued={0};steps=0
    while queue:
        at=queue.popleft();queued.remove(at);s=states[at].copy();i=ins[at];op=i['opcode'];r=i['registers'];ref=i.get('reference','');ret=None
        if op.startswith('const-string'):s[r[0]]=('str',ref)
        elif op=='const-class':s[r[0]]=('class',ref)
        elif op.startswith('const'):s[r[0]]=('int',i.get('literal'))
        elif op.startswith('move-result'):
            v=s.get('$ret');s.pop(r[0],None)
            if v is not None:s[r[0]]=v
        elif op.startswith('move') and op!='move-exception':
            v=s.get(r[1]);s.pop(r[0],None)
            if v is not None:s[r[0]]=v
        elif op.startswith('invoke-'):
            args=[s.get(k) for k in r]
            if ref.startswith('Ljava/lang/Class;->forName(') and args and args[0] and args[0][0]=='str':ret=('class','L'+args[0][1].replace('.','/')+';')
            elif ref.startswith('Ljava/lang/ClassLoader;->loadClass(') and len(args)>1 and args[1] and args[1][0]=='str':ret=('class','L'+args[1][1].replace('.','/')+';')
            elif ref.startswith(('Ljava/lang/Class;->getMethod(','Ljava/lang/Class;->getDeclaredMethod(')) and len(args)>1 and args[0] and args[0][0]=='class' and args[1] and args[1][0]=='str':ret=('method',args[0][1],args[1][1])
            elif ref.startswith('Ljava/lang/Class;->getName()') and args and args[0] and args[0][0]=='class':ret=('str',args[0][1][1:-1].replace('/','.'))
            elif ref=='Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;' and len(args)==2 and all(a and a[0]=='str' for a in args):ret=('str',args[0][1]+args[1][1])
            s.pop('$ret',None)
            if ret is not None:s['$ret']=ret
        elif op.startswith('filled-new-array'):s.pop('$ret',None)
        elif op not in ('check-cast',) and r and not op.startswith(('if-','return','throw','goto','iput','sput','aput','monitor','packed-switch','sparse-switch','fill-array-data')):
            s.pop(r[0],None)
        if r and (op.startswith(('const-wide','move-wide','move-result-wide','iget-wide','sget-wide','aget-wide')) or
                  op.startswith(('add-long','sub-long','mul-long','div-long','rem-long','and-long','or-long','xor-long','shl-long','shr-long','ushr-long','neg-long','not-long','add-double','sub-double','mul-double','div-double','rem-double','neg-double')) or
                  op.endswith(('-to-long','-to-double'))):
            s.pop(r[0]+1,None)
        if not op.startswith(('invoke-','move-result')):s.pop('$ret',None)
        for target,exception in edges[at]:
            outgoing=s
            if exception:
                outgoing={k:v for k,v in states[at].items() if k!='$ret'}
                writes=bool(r) and op!='check-cast' and not op.startswith(('invoke-','filled-new-array','fill-array-data','if-','return','throw','goto','iput','sput','aput','monitor','packed-switch','sparse-switch'))
                if writes:
                    outgoing.pop(r[0],None)
                    if 'wide' in op:outgoing.pop(r[0]+1,None)
            new=outgoing.copy() if target not in states else {k:v for k,v in states[target].items() if k in outgoing and v==outgoing[k]}
            if target not in states or new!=states[target]:
                states[target]=new
                if target not in queued:queue.append(target);queued.add(target)
        steps+=1;assert steps<1000000
    return states
def group(m):
    owner=m.split('->')[0]
    if owner=='Lcom/panasonic/jp/lumixlab/util/v;':return 'App OS/Harmony compatibility'
    if owner=='Lcom/panasonic/jp/lumixlab/database/AppDatabase;':return 'App Room generated implementation loading'
    if owner=='Lcom/panasonic/jp/lumixlab/LlcApplication;':return 'App native bootstrap'
    if 'onnxruntime' in owner:return 'ONNX native loader'
    if any(x in owner for x in ('techorfilter','libyuv','gpuimage','FFmpeg')):return 'image/media native bootstrap'
    if any(x in owner for x in ('DynamiteModule','dynamite/','ProviderInstaller')):return 'Google external module/security provider'
    if owner.startswith('Lcom/google/'):return 'Google SDK reflection'
    if owner.startswith('Lcom/adobe/'):return 'Adobe notification compatibility'
    if owner.startswith(('Lq8/','Lr8/')):return 'HTTP/TLS platform compatibility candidate'
    if owner.startswith('LA9/'):return 'TLS provider compatibility candidate'
    if 'protobuf' in owner or 'gson' in owner:return 'serialization reflection'
    return 'framework/obfuscated reflection; semantics pending'
def safe(v):
    if v is None:return None
    if v[0]=='int':return list(v)
    if v[0] in ('class','method'):return list(v)
    if v[0]=='str' and re.fullmatch(r'[A-Za-z0-9_.$/;-]{1,180}',v[1]):return list(v)
    return ['redacted_constant_sha256',sha(str(v).encode())]
def main():
    raw={m['method']:m for m in rows(WORK/'instructions.jsonl')};seed=load(RESULTS/'dynamic_seed.json')['candidates'];out=[];cache={}
    for r in seed:
        m=raw[r['caller']]
        if r['caller'] not in cache:cache[r['caller']]=flow(m)
        i=next(i for i in m['instructions'] if i['offset_cu']==r['offset_cu']);s=cache[r['caller']].get(r['offset_cu'],{})
        args=[s.get(k) for k in i['registers']];target=r['target'];v=None
        if 'Class;->forName(' in target:v=args[0] if args else None
        elif 'ClassLoader;->loadClass(' in target:v=args[1] if len(args)>1 else None
        elif 'Method;->invoke(' in target:v=args[0] if args else None
        elif 'System;->load' in target:v=args[0] if args else None
        status='exact literal target recovered' if v and v[0] in ('str','method') else 'target/runtime argument unresolved'
        out.append({**r,'category':group(r['caller']),'namespace':namespace(r['caller']),'resolution':status,
                    'literal_target':safe(v),'argument_facts':[safe(v) for v in args],
                    'opcode':i['opcode'],'method_target_signature_limit':'Reflection overload/argument-array types not inferred; class/name recovery is not runtime invocation proof.'})
    save(RESULTS/'dynamic_classification.json',{'candidates':out,'category_counts':dict(collections.Counter(r['category'] for r in out)),
         'resolution_counts':dict(collections.Counter(r['resolution'] for r in out)),
         'method':'Worklist CFG constant intersection, switch and exception edges, const/move/class/forName/loadClass/getMethod/concat; computed fields/arrays/builders/interprocedural values remain unknown.',
         'scope':'243 exact inherited candidates only; semantic category and exact target resolution are separate. All literal string values are filtered before publication.'})
    print('Classified',len(out),'dynamic sites;',dict(collections.Counter(r['resolution'] for r in out)))
if __name__=='__main__':main()
