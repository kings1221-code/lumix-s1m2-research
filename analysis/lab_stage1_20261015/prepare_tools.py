"""Verify cached official Ghidra/JDK distributions and extract into an isolated local directory."""
import argparse,hashlib,json,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
TOOLS=[('ghidra','ghidra_12.1.4_PUBLIC_20260921.zip','ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'),
       ('jdk25','OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip','00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283')]
records=[]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--cache',type=Path,default=ROOT/'downloads/archives/tools');args=parser.parse_args()
for name,filename,expected in TOOLS:
    archive=args.cache/filename
    with archive.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
    assert actual==expected,(name,'official SHA-256 mismatch')
    destination=ROOT/'.research-local/stage1/tools'/name
    marker=destination/'.archive-sha256'
    if not destination.exists():
        destination.mkdir(parents=True)
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                assert (destination/member.filename).resolve().is_relative_to(destination.resolve())
            z.extractall(destination)
        marker.write_text(expected)
    else:
        assert marker.read_text()==expected
    records.append({'name':name,'archive':filename,'size':archive.stat().st_size,'sha256':actual,'official_sha256_matches':True})
(ROOT/'.research-local/stage1/tool_verification.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8',newline='\n')
print('PASS: verified official Ghidra 12.1.4 and Temurin JDK 25.0.4.1+1')
