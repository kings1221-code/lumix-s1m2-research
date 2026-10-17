"""Independent self-written model of the inspected LUT math; NEVER loads target SO.
Finite valid grids only. This does not claim bit-exact native execution equivalence.
"""
import itertools,math,random,struct
from common import *
def f32(x):return struct.unpack('<f',struct.pack('<f',x))[0]
def grid(n,fn):return [tuple(fn(r/(n-1),g/(n-1),b/(n-1))) for b in range(n) for g in range(n) for r in range(n)]
def coordinates(n,p):
    assert n>=2 and all(math.isfinite(v) for v in p)
    step=f32(1.0/f32(n-1))
    low=[max(0,min(n-2,math.floor(v/step))) for v in p]
    local=[(v-step*k)/step for v,k in zip(p,low)]
    return low,local
def sample_branch(n,data,p):
    low,(r,g,b)=coordinates(n,p);ri,gi,bi=low
    def vertex(dr,dg,db):return data[(bi+db)*n*n+(gi+dg)*n+ri+dr]
    if r<=g:
        if b<=g:
            if b<=r:order='GRB';vs=[vertex(0,0,0),vertex(0,1,0),vertex(1,1,0),vertex(1,1,1)];ws=[1-g,g-r,r-b,b]
            else:order='GBR';vs=[vertex(0,0,0),vertex(0,1,0),vertex(0,1,1),vertex(1,1,1)];ws=[1-g,g-b,b-r,r]
        else:order='BGR';vs=[vertex(0,0,0),vertex(0,0,1),vertex(0,1,1),vertex(1,1,1)];ws=[1-b,b-g,g-r,r]
    elif g<=b:
        if r<=b:order='BRG';vs=[vertex(0,0,0),vertex(0,0,1),vertex(1,0,1),vertex(1,1,1)];ws=[1-b,b-r,r-g,g]
        else:order='RBG';vs=[vertex(0,0,0),vertex(1,0,0),vertex(1,0,1),vertex(1,1,1)];ws=[1-r,r-b,b-g,g]
    else:order='RGB';vs=[vertex(0,0,0),vertex(1,0,0),vertex(1,1,0),vertex(1,1,1)];ws=[1-r,r-g,g-b,b]
    return tuple(sum(w*v[c] for w,v in zip(ws,vs)) for c in range(3)),order,ws
def sample_sorted(n,data,p):
    low,u=coordinates(n,p);order=sorted(range(3),key=lambda a:u[a],reverse=True)
    vertices=[low.copy()];current=low.copy()
    for axis in order:current=current.copy();current[axis]+=1;vertices.append(current)
    ws=[1-u[order[0]],u[order[0]]-u[order[1]],u[order[1]]-u[order[2]],u[order[2]]]
    def value(v):return data[v[2]*n*n+v[1]*n+v[0]]
    return tuple(sum(w*value(v)[c] for w,v in zip(ws,vertices)) for c in range(3))
def compose(n_a,a,n_b,b):return [sample_branch(n_b,b,p)[0] for p in a]
def write_cube(n,data):
    assert n>=2 and len(data)==n**3
    return (f'LUT_3D_SIZE {n}\n\n'+''.join('%.7f %.7f %.7f\n'%p for p in data)).encode('ascii')
def main():
    rng=random.Random(20261017);cases=0;orders=set();maxdiff=0.0;identity_error=0.0
    points=list(itertools.permutations((0.17,0.43,0.79)))+[(0,0,0),(1,1,1),(.5,.5,.5),(0,1,.5),(-.2,.4,1.2)]
    points += [tuple(rng.uniform(-.1,1.1) for _ in range(3)) for _ in range(250)]
    for n in (2,3,4,17):
        nonlinear=grid(n,lambda r,g,b:(r*g+.1*b,g*b+.2*r,b*r+.3*g))
        ident=grid(n,lambda *p:p)
        for p in points:
            a,order,ws=sample_branch(n,nonlinear,p);z=sample_sorted(n,nonlinear,p)
            diff=max(abs(a[i]-z[i]) for i in range(3));maxdiff=max(maxdiff,diff);assert diff<2e-12
            assert abs(sum(ws)-1)<1e-12;orders.add(order);cases+=1
            q=sample_branch(n,ident,p)[0];identity_error=max(identity_error,max(abs(q[i]-p[i]) for i in range(3)))
    assert len(orders)==6
    a=grid(3,lambda r,g,b:(b,r,g));b=grid(2,lambda r,g,b:(1-r,g,.5*b));out=compose(3,a,2,b)
    expect=[(1-p[0],p[1],.5*p[2]) for p in a];assert max(abs(x-y) for p,q in zip(out,expect) for x,y in zip(p,q))<1e-12
    encoded=write_cube(3,out);lines=encoded.decode().splitlines();parsed=[tuple(map(float,s.split())) for s in lines[2:]]
    assert lines[:2]==['LUT_3D_SIZE 3',''] and len(parsed)==27
    assert max(abs(x-y) for p,q in zip(out,parsed) for x,y in zip(p,q))<=5.01e-8
    synthetic=WORK/'synthetic';synthetic.mkdir(exist_ok=True)
    for name,value in [('input_a.cube',write_cube(3,a)),('input_b.cube',write_cube(2,b)),('output_model.cube',encoded)]:
        p=synthetic/name
        if p.exists():assert p.read_bytes()==value
        else:p.write_bytes(value)
    # Byte-verify selected original instructions which constrain the model.
    x=load(ROOT/'.research-local/full_reverse/native_results_refined/libcube_merge.so.json')
    fn=next(f for f in x['functions'] if f['elf_va']=='0x5714')
    selected=[i for i in fn['instructions'] if i['instruction'].startswith(('fcvtms','fdiv s','fcvt d0,s','fcmp','b.le'))]
    assert any(i['instruction']=='fcvtms w8,d0' for i in selected)
    assert any(i['instruction']=='fdiv s0,s0,s1' for i in selected)
    from elftools.elf.elffile import ELFFile
    path=SOURCE/'extracted/arm64/lib/arm64-v8a/libcube_merge.so'
    with path.open('rb') as f:
        elf=ELFFile(f);blob=path.read_bytes()
        for i in selected:
            va=int(i['address'],16)-x['image_base'];seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz'])
            at=seg['p_offset']+va-seg['p_vaddr'];assert blob[at:at+4].hex()==i['bytes']
    save(RESULTS/'lut_synthetic.json',{'status':'PASS','library':path.name,**identity(path),'evaluator_ELF_va':'0x5714','writer_ELF_va':'0x4fdc','composition_ELF_va':'0x4e60',
         'model_cases':cases,'six_regions':sorted(orders),'independent_sorted_tetrahedron_max_abs_difference':maxdiff,
         'identity_grid_max_abs_error_including_float32_spacing':identity_error,'composition_control':'3^3 A-grid channel permutation -> 2^3 B-grid affine transform',
         'output_format':{'header':'LUT_3D_SIZE %d\\n\\n','row':'%.7f %.7f %.7f\\n','rows':27,'R_fastest_then_G_then_B':True},
         'synthetic_files':[{'file':p.name,**identity(p)} for p in sorted(synthetic.glob('*.cube'))],
         'original_instruction_controls':selected,
         'correction':'Ghidra C casts obscure ARM64 FCVTMS (floor), and step is float32 division promoted to double. Finite-cell model reflects both. No coordinate clamp to [0,1]; cell indices clamp while fractional coordinates may extrapolate.',
         'limits':'Self-written model vs independent mathematical formula plus original instruction constraints; target SO NOT executed or emulated. Not native bit-exact verification, malformed-input safety, NaN/Inf, integer overflow, locale or all printf rounding equivalence.'})
    print('PASS LUT model:',cases,'cases, 6 regions, composition and 27-row format; native target execution false')
if __name__=='__main__':main()
