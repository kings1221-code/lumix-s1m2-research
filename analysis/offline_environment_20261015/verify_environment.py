"""Smoke-check known official tools; parse ELF headers only, never load target libraries."""
import argparse
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCAL = ROOT / '.research-local'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('Output must not exist')
    import capstone
    from elftools.elf.elffile import ELFFile
    checks = []
    for name, expected in [('capstone', '5.0.9'), ('pyelftools', '0.33')]:
        actual = importlib.metadata.version(name)
        checks.append({'name': name + '_version', 'value': actual, 'pass': actual == expected})
    # Synthetic ARM64 RET is disassembled as data; it is never executed.
    instruction = list(capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN).disasm(bytes.fromhex('c0035fd6'), 0))
    checks.append({'name': 'synthetic_arm64_ret', 'pass': len(instruction) == 1 and instruction[0].mnemonic == 'ret'})
    elf_header = b'\x7fELF\x02\x01\x01' + b'\0' * 9 + struct.pack('<HHIQQQIHHHHHH', 3, 183, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    elf = ELFFile(io.BytesIO(elf_header))
    checks.append({'name': 'synthetic_elf64_aarch64', 'pass': elf['e_machine'] == 'EM_AARCH64' and elf.elfclass == 64})
    archives = []
    for item in json.loads((HERE / 'toolchain.lock.json').read_text(encoding='utf-8'))['tools']:
        archive = LOCAL / 'downloads' / item['filename']
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        archives.append({'id': item['id'], 'sha256': actual, 'pass': actual == item['sha256']})
    if not all(x['pass'] for x in archives):
        raise SystemExit('Tool archive integrity failure; refusing tool execution')
    java = LOCAL / 'tools/jre/jdk-21.0.12.1+1-jre/bin/java.exe'
    java_version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True, timeout=30)
    command = [str(java), '-cp', str(LOCAL / 'tools/jadx/lib/*'), 'jadx.cli.JadxCLI']
    jadx_version = subprocess.run(command + ['--version'], capture_output=True, text=True, check=True, timeout=30)
    help_text = subprocess.run(command + ['--help'], capture_output=True, text=True, check=True, timeout=30).stdout
    checks.append({'name': 'java_version', 'value': (java_version.stdout + java_version.stderr).strip(), 'pass': '21.0.12.1' in java_version.stderr})
    checks.append({'name': 'jadx_version', 'value': jadx_version.stdout.strip(), 'pass': jadx_version.stdout.strip() == '1.5.6'})
    checks.append({'name': 'jadx_static_options', 'pass': all(x in help_text for x in ['--single-class', '--decompilation-mode', '--output-dir'])})
    native = []
    if args.source_root:
        for target in sorted((args.source_root / 'extracted/arm64/lib/arm64-v8a').glob('*.so')):
            with target.open('rb') as stream:
                parsed = ELFFile(stream)
                native.append({'name': target.name, 'e_machine': parsed['e_machine'], 'bits': parsed.elfclass,
                               'pass': parsed['e_machine'] == 'EM_AARCH64' and parsed.elfclass == 64})
        checks.append({'name': '18_native_headers_read', 'pass': len(native) == 18 and all(x['pass'] for x in native)})
    result = {'python': sys.version, 'host': platform.platform(), 'machine': platform.machine(),
              'scope': 'official_tool_versions_help_synthetic_disassembly_and_native_headers',
              'target_execution': False, 'archives': archives, 'checks': checks, 'native_headers': native,
              'pass': all(x['pass'] for x in checks)}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(f"{'PASS' if result['pass'] else 'FAIL'}: {len(checks)} environment checks; target execution=False")
    if not result['pass']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
