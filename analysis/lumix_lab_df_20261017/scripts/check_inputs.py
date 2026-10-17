from common import *
def main():
    x=load(PREV/'results/input_manifest.json')
    for r in x['inputs']:
        p=Path(r['path_token'].replace('<SOURCE_ROOT>',str(SOURCE))) if r['kind']=='APK' else SOURCE/'extracted/base'/r['member'] if r['kind']=='DEX' else SOURCE/'extracted/arm64'/r['member']
        assert identity(p)=={k:r[k] for k in ('size','sha256')}
    save(RESULTS/'input_manifest.json',x)
    save(RESULTS/'dependency_manifest.json',{'baseline':'0de47d702ef058cea3b39dabf521a7754f0003a1','private_metadata_inputs':[
       {'token':name,**identity(ROOT/name)} for name in ('.research-local/stage1/dex_index_v2.jsonl','.research-local/stage1/elf_inventory.json')],
       'tools':{'JADX':'1.5.6 (dexlib2)','Java':'25.0.4.1','Ghidra':'12.1.4','Python':'3.12.14','pyelftools':'0.33','Capstone':'5.0.9'},
       'limits':'Private metadata identities only; contents/binaries not published. Source sample identities separately rechecked; original publisher trust not newly revalidated.'})
    print('PASS: 25 original inputs and inherited metadata identities')
if __name__=='__main__':main()
