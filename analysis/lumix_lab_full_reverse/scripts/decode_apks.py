"""Run hash-verified official Apktool on original APKs, decoded outputs only."""
import subprocess
from common import *

def main():
    jar=ROOT/'downloads/archives/tools/apktool_3.0.3.jar'
    assert file_id(jar)['sha256']=='dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423'
    java=ROOT/'.research-local/stage1/tools/jdk25/jdk-25.0.4.1+1/bin/java.exe'
    records=[]
    for r in load(RESULTS/'input_manifest.json')['inputs']:
        if r['kind']!='APK':continue
        name=Path(r['path_token']).name
        path=SOURCE/'apk'/name
        output=WORK/'apktool'/name.removesuffix('.apk')
        assert not output.exists()
        cmd=[str(java),'-Xmx2g','-Duser.home='+str(WORK/'java-home'),'-jar',str(jar),'d','-s',
             '-p',str(WORK/'framework'),'-o',str(output),str(path)]
        result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=240)
        log=WORK/(name+'.apktool.log');log.write_bytes(result.stdout)
        records.append({'apk':name,'exit_code':result.returncode,'log_id':file_id(log),
                        'manifest':file_id(output/'AndroidManifest.xml') if (output/'AndroidManifest.xml').exists() else None})
        print(name,'exit',result.returncode,flush=True)
        if result.returncode:raise RuntimeError(result.stdout.decode(errors='replace'))
    save(RESULTS/'apktool_execution.json',{'tool':{'name':'Apktool','version':'3.0.3',**file_id(jar),
         'official_source':'https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3',
         'checksum_basis':'existing verified official release metadata; local jar matched before decode'},
         'options':['decode','--no-src','new output','local framework cache'], 'apks':records,'target_execution':False})

if __name__=='__main__':main()
