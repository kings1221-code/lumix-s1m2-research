import collections,re,xml.etree.ElementTree as ET
from common import *
def main():
    recovered=load(RESULTS/'resource_resolution.json')['entries'];names=collections.defaultdict(set)
    for r in recovered:names[r['name']].add(r['id'])
    refs=[];unparsed=[];root=ROOT/'.research-local/full_reverse/apktool'
    for p in root.rglob('*.xml'):
        if p.name=='public.xml':continue
        try:tree=ET.parse(p)
        except (ET.ParseError,UnicodeDecodeError):unparsed.append(p.relative_to(root).as_posix());continue
        for e in tree.iter():
            for attribute,value in list(e.attrib.items())+[('<text>',e.text or '')]:
                for name in re.findall(r'@(?:\*?[\w.]+:)?drawable/([\w.]+)',value):
                    if name in names:refs.append({'file':p.relative_to(root).as_posix(),'tag':e.tag,'attribute':attribute,'name':name,'ids':sorted(names[name])})
    save(RESULTS/'resource_symbolic_uses.json.gz',{'references':refs,'files':len({r['file'] for r in refs}),'unique_resolved_ids_referenced':len({i for r in refs for i in r['ids']}),
      'non_text_or_non_XML_files_not_parsed':unparsed,'limits':'Symbolic drawable references from existing decoded XML only; not every raw binary XML, DEX getDrawable call, Android configuration or UI reachability. Resource identity now resolved; complete UI semantics still pending.'},True)
    print('PASS',len(refs),'symbolic drawable uses in',len({r['file'] for r in refs}),'XML files')
if __name__=='__main__':main()
