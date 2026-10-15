#!/usr/bin/env python3
"""Bounded tool readiness: trusted JADX class and synthetic ARM64 ELF; no APK execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, default=Path('/workspace/research-tools'))
    parser.add_argument('--output', type=Path, required=True, help='New directory outside the checkout')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.output.resolve()
    if out == root or out.is_relative_to(root):
        parser.error('Use a new directory outside the repository')
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(argv):
        result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=90)
        commands.append({'argv': list(map(str, argv)), 'exit_code': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        result.check_returncode()
        return result.stdout

    version = run([args.tools/'bin/jadx', '--version']).strip()
    jar = args.tools/'jadx-1.5.6/lib/jadx-1.5.6-all.jar'
    member = 'jadx/core/Consts.class'
    with zipfile.ZipFile(jar) as archive:
        fixture = archive.read(member)
    (out/'Consts.class').write_bytes(fixture)
    run([args.tools/'bin/jadx', '-j', '1', '--no-res', '-d', out/'decompiled', out/'Consts.class'])
    java = out/'decompiled/sources/jadx/core/Consts.java'
    if not java.is_file() or 'package jadx.core;' not in java.read_text():
        raise RuntimeError('JADX did not produce the expected single-class source')
    assembly = out/'synthetic.S'
    assembly.write_text('.text\n.global static_probe\nstatic_probe:\n  nop\n  ret\n')
    run([args.tools/'bin/aarch64-linux-gnu-as', '-o', out/'synthetic.o', assembly])
    elf = run([args.tools/'bin/aarch64-linux-gnu-readelf', '-h', out/'synthetic.o'])
    disassembly = run([args.tools/'bin/aarch64-linux-gnu-objdump', '-d', out/'synthetic.o'])
    if 'AArch64' not in elf or 'nop' not in disassembly or 'ret' not in disassembly:
        raise RuntimeError('ARM64 ELF/readelf/objdump check failed')
    report = {'status': 'PASS', 'jadx_version': version,
              'jadx_fixture': {'archive': jar.name, 'member': member,
                               'sha256': hashlib.sha256(fixture).hexdigest()},
              'aarch64_synthetic_elf': 'PASS', 'target_code_executed': False,
              'vendor_apk_dex_native_test': 'NOT RUN: original files absent'}
    (out/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
