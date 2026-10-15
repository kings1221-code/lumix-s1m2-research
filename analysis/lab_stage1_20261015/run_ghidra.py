"""Run verified Ghidra directly through its Java entry point; avoids Windows batch quoting."""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
work=ROOT/'.research-local/stage1'
ghidra=work/'tools/ghidra/ghidra_12.1.4_PUBLIC'
java=work/'tools/jdk25/jdk-25.0.4.1+1/bin/java.exe'
source=Path(json.loads((ROOT/'.research-local/local_paths.json').read_text(encoding='utf-8'))['source_root'])
inventory=json.loads((work/'elf_inventory.json').read_text(encoding='utf-8'))['libraries']
targets=[]
for library in inventory:
 targets.extend(library['library']+'|'+t['function_va'] for t in library['dynamic_jni_candidates'])
 if library['library']=='libffmpeg_mediametadataretriever_jni.so':
  targets.extend(library['library']+'|'+s['va'] for s in library['symbols'] if s['defined'] and any(k in s['name'] for k in ['register_wseemann','RegisterNatives','FindClass']))
(work/'native_targets.txt').write_text('\n'.join(sorted(set(targets)))+'\n',encoding='utf-8',newline='\n')
project=Path(__file__).resolve().parent/'local/ghidra-project'
project.mkdir(parents=True,exist_ok=True)
for lib in ['libllc.so','libffmpeg_mediametadataretriever_jni.so','libonnxruntime4j_jni.so','libyuv_android.so']:
 command=[str(java),'-Xmx3g','-Xshare:off','--enable-native-access=ALL-UNNAMED','-Djava.system.class.loader=ghidra.GhidraClassLoader',
          '-Dfile.encoding=UTF8','-Djava.awt.headless=true','-Duser.home='+str(work/'ghidra-home'),
          '-Dapplication.settingsdir='+str(work/'ghidra-settings'),'-Dapplication.cachedir='+str(work/'ghidra-cache'),'-Dapplication.tempdir='+str(work/'ghidra-temp'),
          '-cp',str(ghidra/'Ghidra/Framework/Utility/lib/Utility.jar'),
          'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(project),'Stage1',
          *(['-process',lib,'-noanalysis'] if '--reprocess' in sys.argv else ['-import',str(source/'extracted/arm64/lib/arm64-v8a'/lib),'-analysisTimeoutPerFile','120']),
          '-scriptPath',str(Path(__file__).resolve().parent),'-postScript','ExportStage1.java',str(work/'ghidra_results'),str(work/'native_targets.txt')]
 with (work/('ghidra_direct_'+lib+'.log')).open('w',encoding='utf-8') as out:
  r=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=300)
 print(lib,'exit',r.returncode,flush=True)
