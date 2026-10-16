"""Create private paths and exact Git snapshots in a new replay directory."""
import argparse
from common import ROOT, WORK, file_id, save, git

REFERENCES = {
    'boot': ('3362325de9e36e067f1826575f0fffde24ed98fd', 'analysis/s5m2_boot_consumer_audit_20261014/',
             ['README.md','audit_sources.py','results_checked/source_audit.json']),
    'corpus': ('0e9e45c54a6cadf9095a612fe03d34839ef638ff', 'analysis/s5m2_full_corpus_audit_20261014/',
               ['corpus_audit.py','results/data/corpus.json','results/data/inventory.json','results/data/comparisons.json']),
}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source-root',required=True)
    p.add_argument('--oss-root',required=True)
    p.add_argument('--v31-zip',required=True)
    p.add_argument('--v37-zip',required=True)
    a=p.parse_args()
    WORK.mkdir(parents=True,exist_ok=False)
    save(WORK/'paths.json',{'source_root':a.source_root,'oss_root':a.oss_root,
         'firmware':{'S5M2_V31':a.v31_zip,'S5M2_V37':a.v37_zip}})
    manifest=[]
    for label,(rev,base,names) in REFERENCES.items():
        for name in names:
            dest=WORK/'references'/label/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open('xb') as f:
                f.write(git('show',rev+':'+base+name))
            manifest.append({'commit':rev,'path':base+name,'snapshot_relative':str(dest.relative_to(WORK)),**file_id(dest)})
    save(WORK/'reference_manifest.json',manifest)
    print('PASS: exact historical references and private input paths saved; no branch merging')

if __name__=='__main__':
    main()
