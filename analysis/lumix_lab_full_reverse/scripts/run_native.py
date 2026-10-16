import subprocess,sys
import os
from common import *
def main():
    tool=ROOT/'.research-local/stage1/tools';ghidra=tool/'ghidra/ghidra_12.1.4_PUBLIC';java=tool/'jdk25/jdk-25.0.4.1+1/bin/java.exe'
    refine='--refine' in sys.argv
    fix='--fix-prototype' in sys.argv
    if refine and not (WORK/'native_targets_refined.txt').exists():
        initial=load(WORK/'native_results/libcube_merge.so.json');seen={f['entry'] for f in initial['functions']}
        extra=sorted({int(c['entry'],16)-initial['image_base'] for f in initial['functions'] for c in f['callees'] if not c['external'] and not c['thunk'] and c['entry'] not in seen})
        with (WORK/'native_targets_refined.txt').open('x',encoding='utf-8') as f:
            f.write((WORK/'native_targets.txt').read_text(encoding='utf-8'))
            f.write(''.join('libcube_merge.so|'+hex(va)+'\n' for va in extra))
    for lib in (('libcube_merge.so',) if refine or fix else ('libllc.so','libcube_merge.so')):
        project=ROOT/'analysis/lab_stage1_20261015/local/ghidra-project' if lib=='libllc.so' else Path(os.environ.get('LUMIX_FULL_PROJECT',BASE/'local/ghidra-project'))
        project.mkdir(parents=True,exist_ok=True)
        mode=['-process',lib,'-noanalysis','-readOnly'] if lib=='libllc.so' or refine or fix else ['-import',str(SOURCE/'extracted/arm64/lib/arm64-v8a'/lib),'-analysisTimeoutPerFile','120']
        cmd=[str(java),'-Xmx3g','-Xshare:off','--enable-native-access=ALL-UNNAMED','-Djava.system.class.loader=ghidra.GhidraClassLoader','-Dfile.encoding=UTF8','-Djava.awt.headless=true',
             '-Duser.home='+str(WORK/'ghidra-home'),'-Dapplication.settingsdir='+str(WORK/'ghidra-settings'),'-Dapplication.cachedir='+str(WORK/'ghidra-cache'),'-Dapplication.tempdir='+str(WORK/'ghidra-temp'),
             '-cp',str(ghidra/'Ghidra/Framework/Utility/lib/Utility.jar'),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(project),'Stage1' if lib=='libllc.so' else 'FullReverse',*mode,
             '-scriptPath',str(BASE/'scripts'),'-postScript','FixNativePrototype.java' if fix else 'ExportNative.java',str(WORK/('native_prototype_fixed' if fix else 'native_results_refined' if refine else 'native_results')),str(WORK/('native_targets_refined.txt' if refine else 'native_targets.txt'))]
        with (WORK/(lib+('.prototype_fixed' if fix else '.refined' if refine else '')+'.ghidra.log')).open('x',encoding='utf-8') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=300)
        print(lib,'exit',r.returncode,flush=True)
        if r.returncode:raise RuntimeError('Ghidra failure; inspect local log')
if __name__=='__main__':main()
