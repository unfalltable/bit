"""Install portable, first-party development tools only within feasibility/.tools."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import shutil
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.tools'
DOWNLOADS = TOOLS / 'downloads'
REPORTS = ROOT / 'reports'
for folder in [TOOLS, DOWNLOADS, REPORTS]:
    folder.mkdir(parents=True, exist_ok=True)

PACKAGES = [
    ('go', 'https://go.dev/dl/go1.27.1.windows-amd64.zip', 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'),
    ('adb', 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip', None),
    ('rustc', 'https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-pc-windows-gnu.tar.xz', 'f0e8e33973771acc4d2f87891b19d4f3f2d3827e2e7848c091d7c070bd63479c'),
    ('cargo', 'https://static.rust-lang.org/dist/2026-09-03/cargo-1.98.1-x86_64-pc-windows-gnu.tar.xz', '4bd77f16bd2a26db6eacf9320414d3a792d9998cb5e9ac122280ba56126f2a44'),
    ('rust-std', 'https://static.rust-lang.org/dist/2026-09-03/rust-std-1.98.1-x86_64-pc-windows-gnu.tar.xz', '5bb599a541fcb9c0edc00e512570f60d2262623f1e2a19a44cce3a7a97208788'),
    ('rust-mingw', 'https://static.rust-lang.org/dist/2026-09-03/rust-mingw-1.98.1-x86_64-pc-windows-gnu.tar.xz', '75d898804789c12ca969365f0a86d85c3bca1fdb070f0be615ca513a986b2674'),
    ('rustfmt-preview', 'https://static.rust-lang.org/dist/2026-09-03/rustfmt-1.98.1-x86_64-pc-windows-gnu.tar.gz', 'f0f51c0c5c0c7b1673822c6d77a4eb98e2abfd0fd1fc335fb80103575caed253'),
    ('clippy-preview', 'https://static.rust-lang.org/dist/2026-09-03/clippy-1.98.1-x86_64-pc-windows-gnu.tar.gz', '72d4651d4c87d78dc89d52b13f748ce56c89c5f5c79c3bd9b4f8f09259925904'),
    ('llvm-mingw', 'https://github.com/mstorsjo/llvm-mingw/releases/download/20250812/llvm-mingw-20250812-msvcrt-x86_64.zip', '2140379cf53a9da9e8e38823ea85f64d6e999c766e92c5ea3fd2f8fb3a4ee1c7'),
    ('libclang-wheel', 'https://files.pythonhosted.org/packages/0b/2d/3f480b1e1d31eb3d6de5e3ef641954e5c67430d5ac93b7fa7e07589576c7/libclang-18.1.1-py2.py3-none-win_amd64.whl', '4dd2d3b82fab35e2bf9ca717d7b63ac990a3519c7e312f19fa8e86dcc712f7fb'),
]

def download(package):
    name, url, expected = package
    dest = DOWNLOADS / url.rsplit('/', 1)[1]
    if not dest.exists():
        req = urllib.request.Request(url, headers={'User-Agent': 'BIT-feasibility/1'})
        with urllib.request.urlopen(req, timeout=60) as response, dest.with_suffix(dest.suffix+'.tmp').open('wb') as out:
            shutil.copyfileobj(response, out)
        dest.with_suffix(dest.suffix+'.tmp').replace(dest)
    actual = hashlib.file_digest(dest.open('rb'), 'sha256').hexdigest()
    if expected and actual != expected:
        raise ValueError(f'{name}: publisher SHA256 mismatch')
    print(f'Downloaded {name}: {dest.stat().st_size} bytes, SHA256 {actual}', flush=True)
    return {'name': name, 'url': url, 'sha256': actual, 'expected_sha256': expected, 'size': dest.stat().st_size, 'path': str(dest)}

def install(row):
    dest = Path(row['path'])
    name = row['name']
    if name in ('go', 'adb', 'llvm-mingw'):
        with zipfile.ZipFile(dest) as archive:
            for entry in archive.infolist():
                resolved = (TOOLS / entry.filename).resolve()
                if not resolved.is_relative_to(TOOLS.resolve()):
                    raise ValueError('archive path escape')
            archive.extractall(TOOLS)
    elif name == 'libclang-wheel':
        install_root = TOOLS / 'python-libclang'
        install_root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(dest) as archive:
            for entry in archive.infolist():
                resolved = (install_root / entry.filename).resolve()
                if not resolved.is_relative_to(install_root.resolve()):
                    raise ValueError('wheel path escape')
            archive.extractall(install_root)
    else:
        staging = TOOLS / 'unpacked' / name
        staging.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest) as archive:
            archive.extractall(staging, filter='data')
        package_root = next(staging.iterdir())
        component = package_root / (f'{name}-x86_64-pc-windows-gnu' if name == 'rust-std' else name)
        if not component.is_dir():
            raise ValueError(f'Component not found: {component}')
        shutil.copytree(component, TOOLS / 'rust', dirs_exist_ok=True)
    print(f'Installed local {name}', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-android-tools', action='store_true',
                        help='Explicitly prepare optional ADB; never connects a device')
    args = parser.parse_args()
    selected = [package for package in PACKAGES if package[0] != 'adb' or args.include_android_tools]
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(download, selected))
    (REPORTS/'tool-downloads.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
    for row in rows:
        install(row)
