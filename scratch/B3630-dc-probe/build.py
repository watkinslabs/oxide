"""Build measurement-only PE diagnostics against supplied source headers."""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--wine-source', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
print((args.wine_source / 'VERSION').read_text().strip())
args.out.mkdir(parents=True, exist_ok=True)
source = Path(__file__).with_name('probe.c')
imports = {'kernel32': ['GetStdHandle', 'WriteFile', 'ExitProcess'],
           'user32': ['GetDC', 'ReleaseDC', 'GetDesktopWindow'],
           'gdi32': ['GetTextExtentPointW', 'GetTextMetricsW', 'GetStockObject', 'SelectObject']}
for arch, machine in [('x86_64', 'i386:x86-64'), ('aarch64', 'arm64')]:
    obj = args.out / f'probe-{arch}.obj'
    subprocess.run(['clang', f'--target={arch}-windows-gnu', '-O2', '-DWIN32_LEAN_AND_MEAN',
                    '-I' + str(args.wine_source / 'include'), '-I' + str(args.wine_source / 'include/msvcrt'),
                    '-c', str(source), '-o', str(obj)], check=True)
    libraries = []
    for library, names in imports.items():
        definition = args.out / (library + '.def')
        definition.write_text(f'LIBRARY {library}.dll\nEXPORTS\n' + '\n'.join(names) + '\n')
        archive = args.out / f'{library}-{arch}.lib'
        subprocess.run(['llvm-dlltool', '-m', machine, '-d', str(definition), '-l', str(archive)], check=True)
        libraries.append(str(archive))
    subprocess.run(['lld-link', '/entry:mainCRTStartup', '/subsystem:console', '/nodefaultlib',
                    '/out:' + str(args.out / f'probe-{arch}.exe'), str(obj), *libraries], check=True)
