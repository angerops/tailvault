#!/usr/bin/env python3
"""GitHub transport for verified, resumable TailVault releases.

Authentication stays in gh (GITHUB_TOKEN/GH_TOKEN in CI or its local keyring).
No credential is copied into arguments, release notes, or the cask.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse

from release_common import publish


class Client:
    def __init__(self, repository):
        if repository not in ('angerops/tailvault', 'angerops/tailvault-prerelease'):
            raise RuntimeError('Release publishing is restricted to the TailVault repositories')
        self.repository = repository

    def gh(self, args, payload=None, missing=False):
        result = subprocess.run(['gh', *args], input=payload, capture_output=True)
        if result.returncode:
            error = result.stderr.decode(errors='replace').strip()
            if missing and ('release not found' in error.lower() or '(HTTP 404)' in error):
                return None
            raise RuntimeError('GitHub command failed: ' + error)
        return result.stdout

    def api(self, method, path, payload=None):
        args = ['api', '--hostname', 'github.com', '--method', method,
                'repos/' + self.repository + path]
        if payload is not None:
            args.extend(['--input', '-'])
            payload = json.dumps(payload).encode()
        result = self.gh(args, payload, missing=method == 'GET')
        return json.loads(result) if result else None

    def request(self, method, path, payload=None, content_type=None):
        if method == 'GET' and path.startswith('/releases/tags/'):
            # gh also locates drafts that do not yet have a published Git tag.
            tag = urllib.parse.unquote(path[len('/releases/tags/'):])
            data = self.gh(['release', 'view', tag, '--repo', self.repository,
                            '--json', 'apiUrl'], missing=True)
            if data is None:
                return None
            api_url = json.loads(data)['apiUrl']
            prefix = 'https://api.github.com/repos/' + self.repository + '/releases/'
            if not api_url.startswith(prefix) or not api_url[len(prefix):].isdigit():
                raise RuntimeError('GitHub returned a release outside this repository')
            return self.api('GET', '/releases/' + api_url[len(prefix):])
        upload = re.fullmatch(r'/releases/([0-9]+)/assets\?(.+)', path)
        if method == 'POST' and upload:
            query = urllib.parse.parse_qs(upload[2])
            if set(query) != {'name'} or len(query['name']) != 1:
                raise RuntimeError('Invalid release asset query')
            name = query['name'][0]
            if not re.fullmatch(r'(TailVault-v[0-9]+\.[0-9]+\.[0-9]+-macos-(arm64|amd64)\.zip|SHA256SUMS)', name):
                raise RuntimeError('Invalid release asset name')
            release = self.api('GET', '/releases/' + upload[1])
            with tempfile.TemporaryDirectory(prefix='tailvault-upload-') as folder:
                asset_path = Path(folder) / name
                asset_path.write_bytes(payload)
                asset_path.chmod(0o600)
                self.gh(['release', 'upload', release['tag_name'], str(asset_path),
                         '--repo', self.repository])  # Never --clobber.
            release = self.api('GET', '/releases/' + upload[1])
            matches = [asset for asset in release['assets'] if asset['name'] == name]
            if len(matches) != 1:
                raise RuntimeError('Uploaded release asset is missing or duplicated')
            return matches[0]
        return self.api(method, path, payload)

    def download(self, asset, tag):
        asset_id = asset.get('id')
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise RuntimeError('Invalid GitHub asset identifier')
        # gh handles GitHub's authenticated asset redirects without baking tokens
        # into URLs. Ignore server-supplied browser_download_url entirely.
        return self.gh(['api', '--hostname', 'github.com',
                        'repos/' + self.repository + '/releases/assets/' + str(asset_id),
                        '--header', 'Accept: application/octet-stream'])

    def release_url(self, tag):
        return 'https://github.com/' + self.repository + '/releases/tag/' + tag


def main():
    root = Path(__file__).resolve().parent.parent
    output = root / 'bin/release'
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if commit != os.environ['GITHUB_SHA']:
        raise RuntimeError('Built commit does not match the requested workflow commit')
    files = {name: (output / name).read_bytes() for name in ('SHA256SUMS', 'notarization.json')}
    filename = files['SHA256SUMS'].decode().strip().split(maxsplit=1)[1]
    match = re.fullmatch(r'TailVault-v([0-9]+\.[0-9]+\.[0-9]+)-macos-(arm64|amd64)\.zip', filename)
    if not match:
        raise RuntimeError('Unexpected release archive name')
    version = match[1]
    files[filename] = (output / filename).read_bytes()
    url, published = publish(Client(os.environ['GITHUB_REPOSITORY']), commit, version,
                             os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], files)
    # Recovery may retain an earlier signed ZIP. Generate the cask from the
    # verified published bytes, never from a newly rebuilt, different archive.
    verified = root / 'bin/published'
    verified.mkdir(parents=True, exist_ok=True)
    for name, data in published.items():
        (verified / name).write_bytes(data)
    print('Signed build:', url)


if __name__ == '__main__':
    main()
