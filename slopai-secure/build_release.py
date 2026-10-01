"""Build a source-only ZIP from an explicit allowlist, never from the worktree."""
import argparse
import hashlib
from pathlib import Path
import zipfile


ROOT_FILES = (
    'app.py', 'catalog.py', 'security.py', 'build_release.py',
    'README.md', 'SECURITY_REPORT.md', 'requirements.txt',
    'requirements-audit.txt', '.gitignore',
)
DIRECTORIES = {'templates': {'.html'}, 'static': {'.js', '.css', '.svg', '.png'},
               'tests': {'.py'}, 'audit': {'.json', '.txt', '.patch'}}


def release_files(root):
    selected = [root / name for name in ROOT_FILES]
    for folder, extensions in DIRECTORIES.items():
        directory = root / folder
        if directory.is_symlink():
            raise ValueError(f'Symlink not allowed: {folder}')
        for path in sorted(directory.rglob('*')):
            if path.is_symlink():
                raise ValueError(f'Symlink not allowed: {path.relative_to(root)}')
            if path.is_file() and path.suffix in extensions and not any(
                    part.startswith('.') or part == '__pycache__'
                    for part in path.relative_to(root).parts):
                selected.append(path)
    for path in selected:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Missing file or symlink: {path.relative_to(root)}')
    return sorted(selected)


def build(root, output):
    files = release_files(root)
    if output.resolve() in [path.resolve() for path in files]:
        raise ValueError('Output must not overwrite a source file.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            info = zipfile.ZipInfo('slopai-secure/' + path.relative_to(root).as_posix())
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP integrity check failed.')
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(
        f'{digest}  {output.name}\n', encoding='ascii')
    return digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('dist/slopai-secure.zip'))
    args = parser.parse_args()
    print(build(Path(__file__).resolve().parent, args.output))
