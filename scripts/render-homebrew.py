#!/usr/bin/env python3
"""Render a cask for a specific, checksummed TailVault release archive."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import re

ROOT = Path(__file__).resolve().parent.parent
REPOSITORIES = ('angerops/tailvault', 'angerops/tailvault-prerelease')


def render(repository, tag, checksum, minimum, template):
    if repository not in REPOSITORIES:
        raise ValueError('Unexpected release repository')
    match = re.fullmatch(r'v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))(?:-rc\.[1-9][0-9]*)?', tag)
    if not match or not re.fullmatch(r'[0-9a-f]{64}', checksum):
        raise ValueError('A version tag and SHA-256 checksum are required')
    if minimum != '15.0':
        raise ValueError('Update the cask OS requirement when the application minimum changes')
    fields = {'VERSION': tag[1:], 'APP_VERSION': match[1],
              'SHA256': checksum, 'REPOSITORY': repository}
    for name, value in fields.items():
        template = template.replace('@' + name + '@', value)
    if re.search(r'@[A-Z_]+@', template):
        raise ValueError('Unresolved cask template field')
    return template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', choices=REPOSITORIES, default=REPOSITORIES[0])
    parser.add_argument('--tag', required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    version = args.tag.removeprefix('v').split('-rc.', 1)[0]
    if args.archive.name != 'TailVault-v' + version + '-macos-arm64.zip':
        parser.error('Archive filename must match the requested version and architecture')
    digest = hashlib.sha256()
    with args.archive.open('rb') as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b''):
            digest.update(chunk)
    checksum = digest.hexdigest()
    with (ROOT / 'build/Info.plist').open('rb') as source:
        minimum = plistlib.load(source)['LSMinimumSystemVersion']
    template = (ROOT / 'packaging/homebrew/tailvault.rb.in').read_text()
    result = render(args.repository, args.tag, checksum, minimum, template)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result)
    print('Rendered', args.output, 'for', args.tag, 'with SHA-256', checksum)


if __name__ == '__main__':
    main()
