"""GitHub transport and cask input boundaries; all credentials/artifacts are fake."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


cask = module('render-homebrew')
publisher = module('publish-release')


class CaskTests(unittest.TestCase):
    def render(self, repository='angerops/tailvault', tag='v1.2.3', checksum='a' * 64, minimum='15.0'):
        return cask.render(repository, tag, checksum, minimum,
                           (ROOT / 'packaging/homebrew/tailvault.rb.in').read_text())

    def test_candidate_uses_candidate_tag_and_numeric_app_archive(self):
        output = self.render(repository='angerops/tailvault-prerelease', tag='v1.2.3-rc.2')
        self.assertIn('version "1.2.3-rc.2"', output)
        self.assertIn('github.com/angerops/tailvault-prerelease/releases/download/v#{version}/TailVault-v1.2.3-macos-arm64.zip', output)
        self.assertIn('sha256 "' + 'a' * 64 + '"', output)
        self.assertIn('app "TailVault.app"', output)

    def test_inputs_cannot_inject_ruby_or_change_distribution_owner(self):
        for args in ({'repository': 'other/tailvault'}, {'tag': 'v1.2.3"; system("whoami")'},
                     {'tag': 'v1.2.3-rc.0'}, {'tag': 'v01.2.3'}, {'checksum': 'no_check'},
                     {'minimum': '26.0'}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.render(**args)


class GitHubTests(unittest.TestCase):
    def test_only_owned_staging_and_final_repositories_are_allowed(self):
        for repository in ('angerops/tailvault', 'angerops/tailvault-prerelease'):
            self.assertEqual(publisher.Client(repository).repository, repository)
        for repository in ('other/tailvault', 'angerops/tailvault/../../other', ''):
            with self.assertRaises(RuntimeError): publisher.Client(repository)

    def test_download_is_scoped_by_asset_id_and_never_uses_untrusted_url(self):
        client = publisher.Client('angerops/tailvault-prerelease')
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'archive', b'')) as run:
            data = client.download({'id': 42, 'browser_download_url': 'https://untrusted.example/token'}, 'v1.2.3')
        self.assertEqual(data, b'archive')
        args = run.call_args.args[0]
        self.assertIn('repos/angerops/tailvault-prerelease/releases/assets/42', args)
        self.assertNotIn('https://untrusted.example/token', args)
        for asset_id in (0, -1, True, '42', '../42'):
            with self.assertRaises(RuntimeError): client.download({'id': asset_id}, 'v1.2.3')

    def test_gh_draft_lookup_rejects_foreign_api_url(self):
        client = publisher.Client('angerops/tailvault-prerelease')
        client.gh = lambda *args, **kwargs: json.dumps({'apiUrl': 'https://api.github.com/repos/other/repo/releases/42'}).encode()
        with self.assertRaisesRegex(RuntimeError, 'outside this repository'):
            client.request('GET', '/releases/tags/signed-abc')

    def test_authentication_failure_is_not_treated_as_a_missing_release(self):
        client = publisher.Client('angerops/tailvault-prerelease')
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1, b'', b'HTTP 401: bad credentials')):
            with self.assertRaisesRegex(RuntimeError, 'GitHub command failed'):
                client.request('GET', '/releases/tags/v1.2.3')
