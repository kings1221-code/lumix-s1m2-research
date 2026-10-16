"""Record the final bounded checks in a fresh directory; never re-run scans."""
import argparse
import datetime
import os
import subprocess
import sys
from pathlib import Path
from common import HERE, ROOT, file_id, save, digest

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    records=[]
    for label,script,args in [('unit_tests','test_structure.py',[]),
                               ('final_checks','validate_results.py',['--with-inputs'])]:
        start=datetime.datetime.now(datetime.timezone.utc).isoformat()
        command=[sys.executable,'-B','-X','utf8',str(HERE/script),*args]
        result=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
        log=a.output/(label+'.log')
        with (a.output/(label+'.raw.log')).open('xb') as f:f.write(result.stdout)
        with log.open('xb') as f:f.write(result.stdout.replace(b'\r\n',b'\n'))
        records.append({'check':label,'script':script,'arguments':args,
                        'started_utc':start,'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'exit_code':result.returncode,'log':log.name,**file_id(log),
                        'log_normalization':'CRLF to LF for public Git artifact; raw stdout kept locally',
                        'raw_stdout_sha256':digest(result.stdout)})
        print(label,'exit',result.returncode)
        if result.returncode:
            save(a.output/'execution.json',{'status':'FAILED','checks':records})
            raise SystemExit(result.returncode)
    save(a.output/'execution.json',{'status':'PASS','checks':records,
         'boundary':'7 synthetic format tests + saved-result/raw-input/excerpt checks; no broad scan repeated.'})

if __name__=='__main__':
    main()
