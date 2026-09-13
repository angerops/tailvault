#!/usr/bin/env python3
"""Transfer a bounded, identified app from credential-free build to signing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import zipfile

ARCHIVE = 'TailVault-unsigned.zip'
FILES = {
    'TailVault.app/Contents/MacOS/TailVault': 0o755,
    'TailVault.app/Contents/Info.plist': 0o644,
    'TailVault.app/Contents/Resources/icon.icns': 0o644,
}
LIMIT = 128 << 20
VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'


def context(environ, version):
    repository, commit, run = (environ[name] for name in
                               ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID'))
    if (repository not in ('angerops/tailvault', 'angerops/tailvault-prerelease') or
            not re.fullmatch(r'[0-9a-f]{40}', commit) or
            not re.fullmatch(r'[1-9][0-9]*', run) or not re.fullmatch(VERSION, version)):
        raise ValueError('Invalid release identity')
    return dict(schema=1, repository=repository, commit=commit, run_id=run, version=version)


def release_version(event, ref, default):
    tag = re.fullmatch(r'refs/tags/v(' + VERSION + r')(?:-rc\.[1-9][0-9]*)?', ref)
    if event == 'push' and tag:
        return tag[1]
    if event == 'workflow_dispatch' and ref == 'refs/heads/main' and re.fullmatch(VERSION, default):
        return default
    raise ValueError('Signing requires a version tag or a manual build from main')


def check_info(data, version):
    if len(data) > 65536:
        raise ValueError('Oversized application metadata')
    info = plistlib.loads(data)
    expected = dict(CFBundleExecutable='TailVault', CFBundleIdentifier='computer.anger.tailvault',
                    CFBundleName='TailVault', CFBundleShortVersionString=version,
                    CFBundleVersion=version, LSMinimumSystemVersion='15.0')
    if not isinstance(info, dict) or any(info.get(k) != v for k, v in expected.items()):
        raise ValueError('Application metadata does not match the requested release')


def package(app, output, identity):
    app, output = Path(app), Path(output)
    entries = list(app.rglob('*'))
    if app.is_symlink() or any(p.is_symlink() for p in entries):
        raise ValueError('Unsigned app must not contain links')
    files = {str(p.relative_to(app.parent)): p for p in entries if not p.is_dir()}
    if set(files) != set(FILES) or any(not p.is_file() for p in files.values()):
        raise ValueError('Unsigned app contains unexpected files')
    if sum(p.stat().st_size for p in files.values()) > LIMIT:
        raise ValueError('Unsigned app exceeds the size limit')
    check_info(files['TailVault.app/Contents/Info.plist'].read_bytes(), identity['version'])
    output.mkdir(parents=True, exist_ok=False)
    archive = output / ARCHIVE
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, permissions in FILES.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | permissions) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, files[name].read_bytes())
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'manifest.json').write_text(json.dumps(dict(identity, sha256=checksum)) + '\n')
    return checksum


def unpack(source, destination, identity, expected_sha):
    source, destination = Path(source), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Signing destination must not already exist')
    manifest = source / 'manifest.json'
    archive = source / ARCHIVE
    if (manifest.is_symlink() or archive.is_symlink() or
            manifest.stat().st_size > 4096 or archive.stat().st_size > LIMIT):
        raise ValueError('Invalid build artifact files')
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
        raise ValueError('Invalid expected archive digest')
    if json.loads(manifest.read_text()) != dict(identity, sha256=expected_sha):
        raise ValueError('Build artifact identity does not match this workflow')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_sha:
        raise ValueError('Build artifact checksum mismatch')
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) != len(FILES) or {i.filename for i in entries} != set(FILES):
            raise ValueError('Build artifact contains unexpected or duplicate paths')
        if (sum(i.file_size for i in entries) > LIMIT or
                any(not stat.S_ISREG(i.external_attr >> 16) or i.flag_bits & 1 for i in entries)):
            raise ValueError('Build artifact contains an invalid file type or size')
        contents = {i.filename: bundle.read(i) for i in entries}
    check_info(contents['TailVault.app/Contents/Info.plist'], identity['version'])
    destination.mkdir(mode=0o700, parents=True)
    for name, data in contents.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as target:
            target.write(data)
        path.chmod(FILES[name])
    return destination / 'TailVault.app'


def finalize(app, report, output, version):
    app, report, output = Path(app), Path(report), Path(output)
    if not re.fullmatch(VERSION, version):
        raise ValueError('Invalid release version')
    check_info((app / 'Contents/Info.plist').read_bytes(), version)
    if json.loads(report.read_text()).get('status') != 'Accepted':
        raise ValueError('Notarization must be accepted before packaging')
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    output.mkdir(parents=True, exist_ok=False)
    archive = output / ('TailVault-v' + version + '-macos-arm64.zip')
    subprocess.run(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent',
                    str(app), str(archive)], check=True)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n')
    (output / 'notarization.json').write_bytes(report.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('version', 'package', 'unpack', 'finalize'))
    parser.add_argument('--app', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.operation == 'version':
        with open('build/Info.plist', 'rb') as source:
            default = plistlib.load(source)['CFBundleShortVersionString']
        value = release_version(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], default)
        identity = context(os.environ, value)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        if commit != identity['commit']:
            raise ValueError('Checked out revision does not match the workflow')
        subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'origin/main'], check=True)
        print(value)
        return
    version = os.environ['VERSION']
    if args.operation == 'finalize':
        finalize(args.app, args.report, args.output, version)
        return
    identity = context(os.environ, version)
    if args.operation == 'package':
        checksum = package(args.app, args.output, identity)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('archive_sha256=' + checksum + '\nversion=' + version + '\n')
    else:
        app = unpack(args.input, args.output, identity, os.environ['EXPECTED_ARCHIVE_SHA256'])
        arches = subprocess.check_output(['/usr/bin/lipo', '-archs', str(app / 'Contents/MacOS/TailVault')], text=True)
        if arches.strip() != 'arm64':
            raise ValueError('Expected only an Apple Silicon executable')
        subprocess.run(['/usr/bin/python3', '-I', 'scripts/check-macos-target.py', str(app)], check=True)


if __name__ == '__main__':
    main()
