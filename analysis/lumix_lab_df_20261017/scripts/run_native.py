import subprocess,sys
from common import *
def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'avformat'
    old=ROOT/'.research-local/stage1/tools';ghidra=old/'ghidra/ghidra_12.1.4_PUBLIC';java=old/'jdk25/jdk-25.0.4.1+1/bin/java.exe'
    if mode=='avformat':
        lib='libavformat.so';m=next(l for l in load(RESULTS/'native_import_calls.json.gz')['libraries'] if l['library']==lib)
        sites=[next(c['elf_va'] for c in m['direct_BL_calls'] if c['symbol']==s) for s in ('SSL_connect','SSL_read','SSL_write','inflate')]
        project=Path(os.environ.get('LUMIX_DF_PROJECT',BASE/'local/ghidra-project'));project_name='DF';opts=['-import',str(SOURCE/'extracted/arm64/lib/arm64-v8a'/lib),'-analysisTimeoutPerFile','180']
    elif mode=='cube':
        lib='libcube_merge.so';sites=[f['elf_va'] for f in load(ROOT/'.research-local/full_reverse/native_results_refined/libcube_merge.so.json')['functions']]
        project=PREV/'local/ghidra-project';project_name='FullReverse';opts=['-process',lib,'-noanalysis','-readOnly']
    else:raise ValueError(mode)
    target=WORK/(mode+'_targets.txt')
    if not target.exists():target.write_text(''.join(lib+'|'+v+'\n' for v in sites),encoding='utf-8')
    cmd=[str(java),'-Xmx3g','-Xshare:off','--enable-native-access=ALL-UNNAMED','-Djava.system.class.loader=ghidra.GhidraClassLoader','-Dfile.encoding=UTF8','-Djava.awt.headless=true',
         '-Duser.home='+str(WORK/'ghidra-home'),'-Dapplication.settingsdir='+str(WORK/'ghidra-settings'),'-Dapplication.cachedir='+str(WORK/'ghidra-cache'),'-Dapplication.tempdir='+str(WORK/'ghidra-temp'),
         '-cp',str(ghidra/'Ghidra/Framework/Utility/lib/Utility.jar'),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(project),project_name,*opts,
         '-scriptPath',str(BASE/'scripts'),'-postScript','ExportExact.java',str(WORK/'native'),str(target)]
    project.mkdir(parents=True,exist_ok=True)
    with (WORK/(mode+'.ghidra.log')).open('x',encoding='utf-8') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=360)
    print(mode,'Ghidra exit',r.returncode)
    if r.returncode:raise RuntimeError('Read saved local log')
if __name__=='__main__':main()
