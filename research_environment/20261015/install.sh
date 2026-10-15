#!/usr/bin/env bash
# Install only verified static-analysis utilities; never execute research inputs.
set -euo pipefail
tool_root="${LUMIX_TOOL_ROOT:-/workspace/research-tools}"
download_root="${LUMIX_DOWNLOAD_ROOT:-/workspace/tool-downloads}"
command -v python3 java curl unzip dpkg-deb sha256sum >/dev/null
test "$(uname -sm)" = 'Linux x86_64'
mkdir -p "$tool_root" "$download_root"

fetch_verified() {
    local url="$1" destination="$2" digest="$3"
    if [ ! -f "$destination" ]; then
        local temporary
        temporary="$(mktemp "$download_root/download.XXXXXX")"
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
            --connect-timeout 20 --max-time 180 "$url" --output "$temporary"
        printf '%s  %s\n' "$digest" "$temporary" | sha256sum --check
        mv -n "$temporary" "$destination"
    fi
    printf '%s  %s\n' "$digest" "$destination" | sha256sum --check
}

# Digest published by the official skylot/jadx GitHub release asset.
fetch_verified \
    https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
    "$download_root/jadx-1.5.6.zip" \
    545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974

# Digest from Debian trixie's authenticated Packages index (signed InRelease).
fetch_verified \
    https://deb.debian.org/debian/pool/main/b/binutils/binutils-aarch64-linux-gnu_2.44-3_amd64.deb \
    "$download_root/binutils-aarch64-linux-gnu_2.44-3_amd64.deb" \
    6e5a9be38121213dda42189a525db01aad4dc52194b577d7d73d659a5843ce6c

# Existing installations are compared against verified archives before reuse.
# Conflicts stop setup instead of overwriting local files.
python3 - "$tool_root" "$download_root" <<'PY'
import hashlib, pathlib, subprocess, sys, tempfile, zipfile
root, downloads = map(pathlib.Path, sys.argv[1:])
with tempfile.TemporaryDirectory(prefix='.static-tools-', dir=root) as work:
    work = pathlib.Path(work)
    jadx = work/'jadx-1.5.6'
    with zipfile.ZipFile(downloads/'jadx-1.5.6.zip') as archive:
        for name in archive.namelist():
            if pathlib.PurePosixPath(name).is_absolute() or '..' in pathlib.PurePosixPath(name).parts:
                raise SystemExit('Unsafe archive path')
        archive.extractall(jadx)
    for script in (jadx/'bin').iterdir():
        script.chmod(0o755)
    native = work/'aarch64-binutils'
    subprocess.run(['dpkg-deb','--extract',str(downloads/'binutils-aarch64-linux-gnu_2.44-3_amd64.deb'),str(native)],check=True)
    for source in (jadx, native):
        destination = root/source.name
        if not destination.exists():
            source.rename(destination)
            continue
        for item in source.rglob('*'):
            installed = destination/item.relative_to(source)
            if item.is_symlink():
                if not installed.is_symlink() or item.readlink() != installed.readlink():
                    raise SystemExit(f'Existing installation differs: {installed}')
            elif item.is_file():
                if not installed.is_file() or hashlib.sha256(item.read_bytes()).digest() != hashlib.sha256(installed.read_bytes()).digest():
                    raise SystemExit(f'Existing installation differs: {installed}')
    wrappers = root/'bin'
    wrappers.mkdir(exist_ok=True)
    for name in ('objdump', 'readelf', 'nm', 'as'):
        filename = 'aarch64-linux-gnu-'+name
        body = '#!/usr/bin/env bash\nset -euo pipefail\n'
        body += 'root="$(cd -- "$(dirname -- "$0")/.." && pwd)"\n'
        body += 'export LD_LIBRARY_PATH="$root/aarch64-binutils/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n'
        body += f'exec "$root/aarch64-binutils/usr/bin/{filename}" "$@"\n'
        target = wrappers/filename
        if target.exists() and target.read_text() != body:
            raise SystemExit(f'Refusing to overwrite {target}')
        target.write_text(body)
        target.chmod(0o755)
    target = wrappers/'jadx'
    body = '#!/usr/bin/env bash\nset -euo pipefail\nroot="$(cd -- "$(dirname -- "$0")/.." && pwd)"\nexport JADX_CONFIG_DIR="${JADX_CONFIG_DIR:-$root/state/jadx/config}"\nexport JADX_CACHE_DIR="${JADX_CACHE_DIR:-$root/state/jadx/cache}"\nexec "$root/jadx-1.5.6/bin/jadx" "$@"\n'
    if target.exists() and target.read_text() != body:
        raise SystemExit(f'Refusing to overwrite {target}')
    target.write_text(body)
    target.chmod(0o755)
PY
"$tool_root/bin/jadx" --version
"$tool_root/bin/aarch64-linux-gnu-objdump" --version
