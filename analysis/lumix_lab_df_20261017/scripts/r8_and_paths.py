"""Case-specific R8 Callable edges and bounded firmware call-reference reachability."""
import collections
from common import *
from dynamic import flow,successors
EXTRA=('Ljava/lang/reflect/Constructor;->newInstance(', 'Ljava/lang/reflect/Proxy;->newProxyInstance(',
       'Ljava/lang/Class;->newInstance(', 'Ljava/lang/invoke/MethodHandle;->', 'Ljava/lang/invoke/MethodHandles;->')
def main():
    ms=methods();index={m['method']:m for m in ms};native={m['method'] for m in ms if m['native']}
    dispatch=rows(ROOT/'.research-local/full_reverse/dispatch_instructions.jsonl')
    call=next(m for m in rows(ROOT/'.research-local/full_reverse/semantic_instructions.jsonl') if m['method'].startswith('Lg5/k;->call('))
    switch=next(i for i in call['instructions'] if i['opcode']=='packed-switch')
    payload=next(i for i in call['instructions'] if i['offset_cu']==switch['target_cu'])
    entries={e['key']:switch['offset_cu']+e['relative_target_cu'] for e in payload['switch_elements']}
    default=switch['offset_cu']+switch['width_cu'];edges=successors(call);by={i['offset_cu']:i for i in call['instructions']}
    resolved=[]
    for m in dispatch:
        states=flow(m)
        for c in m['calls']:
            if not c['reference'].startswith('Lg5/k;-><init>'):continue
            i=next(i for i in m['instructions'] if i['offset_cu']==c['offset_cu']);value=states.get(c['offset_cu'],{}).get(i['registers'][1]);assert value and value[0]=='int'
            key=value[1];entry=entries.get(key,default);seen=set();todo=[entry]
            while todo:
                a=todo.pop()
                if a in seen:continue
                seen.add(a);todo.extend(t for t,exc in edges.get(a,[]))
            case_calls=[{'cu':c['offset_cu'],'target':c['reference']} for c in call['calls'] if c['offset_cu'] in seen]
            resolved.append({'caller':m['method'],'constructor_cu':c['offset_cu'],'selector':key,'case_entry_cu':entry,'reachable_case_calls':case_calls,
                             'native_targets':[c['reference'] for c in call['calls'] if c['offset_cu'] in seen and c['reference'] in native]})
    assert len(resolved)==5
    save(RESULTS/'r8_callable_cases.json',{'class':'Lg5/k;','caller_cases':resolved,'switch_entries':entries,'default_entry':default,
         'limits':'Five observed constructor sites; selector from conservative original-Dex CFG propagation. Case CFG includes conditional/exception alternatives; not proof every invocation executes every call. Never apply class-wide callees to all selectors.'})
    # A reference graph is deliberately not a complete Android runtime dispatch graph.
    roots={m['method'] for m in ms if 'Firmware' in m['method'].split('->')[0]}
    roots|={m['method'] for m in ms if any('firmware/' in str(a) for a in m['annotations'])}
    distance={r:0 for r in roots};parent={};queue=collections.deque(roots)
    while queue:
        a=queue.popleft()
        if distance[a]>=8:continue
        for c in index[a]['calls']:
            b=c['reference']
            if b in index and b not in distance:distance[b]=distance[a]+1;parent[b]=(a,c['offset_cu']);queue.append(b)
    def path(m):
        out=[]
        while m in parent:
            p,cu=parent[m];out.append({'caller':p,'cu':cu,'target':m});m=p
        return list(reversed(out))
    sites=load(RESULTS/'dynamic_classification.json')['candidates']
    dynamic_hits=[{**r,'root_distance':distance[r['caller']],'reference_path':path(r['caller'])} for r in sites if r['caller'] in distance]
    crypto=load(RESULTS/'api_usage.json.gz')['sites']
    transforms=[{**r,'root_distance':distance[r['method']],'reference_path':path(r['method'])} for r in crypto if r['method'] in distance]
    more=[{'caller':m['method'],'dex':m['dex'],'cu':c['offset_cu'],'target':c['reference'],'namespace':namespace(m['method'])} for m in ms for c in m['calls'] if c['reference'].startswith(EXTRA)]
    save(RESULTS/'firmware_dynamic_scope.json.gz',{'roots':sorted(roots),'max_reference_depth':8,'defined_methods_reached':len(distance),
         '243_candidate_hits':dynamic_hits,'API_reference_hits':transforms,'additional_dynamic_patterns':EXTRA,'additional_dynamic_sites':more,
         'limits':'Syntactic defined-method invoke graph only; virtual/interface implementations, reflection/runtime class initializers and R8 case sensitivity are not inferred by this BFS. Reachable UI/library code is not firmware-byte taint proof. Additional patterns expose the old 243-index boundary.'},True)
    targets={r['caller'] for r in more if r['caller'].startswith(('Loa/','Lh6/','Lcom/panasonic/'))}
    targets|={m['method'] for m in ms if m['method'].startswith(('Lh6/c;','LI5/d;','Lh6/f;'))}
    with (WORK/'extra_targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(sorted(targets))+'\n')
    review=[m['method'] for m in ms if m['method'].startswith('LD1/Q;-><init>(') or any(c['reference']=='Loa/v0;->b()Ljava/lang/Object;' for c in m['calls'])]
    with (WORK/'review_targets.txt').open('x',encoding='utf-8') as f:f.write('\n'.join(review)+'\n')
    print('PASS 5 Callable selectors;',len(distance),'defined methods within depth8;',len(dynamic_hits),'dynamic hits;',len(more),'additional dynamic API sites;',len(targets),'extra bodies')
if __name__=='__main__':main()
