"""The signer accepts only the bounded app produced by its own build job."""
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('artifact', ROOT / 'scripts/release-artifact.py')
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / 'TailVault.app'
        self.identity = artifact.context(dict(GITHUB_REPOSITORY='angerops/tailvault-prerelease',
                                              GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123'), '0.1.0')
        self.info = dict(CFBundleName='TailVault', CFBundleExecutable='TailVault',
                         CFBundleIdentifier='computer.anger.tailvault', CFBundleVersion='0.1.0',
                         CFBundleShortVersionString='0.1.0', LSMinimumSystemVersion='15.0')
        self.data = {name: b'synthetic bytes' for name in artifact.FILES}
        self.data['TailVault.app/Contents/Info.plist'] = plistlib.dumps(self.info)
        for name, data in self.data.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.input = self.root / 'input'
        self.sha = artifact.package(self.app, self.input, self.identity)
        self.destination = self.root / 'signer'

    def unpack(self, identity=None, sha=None):
        return artifact.unpack(self.input, self.destination, identity or self.identity, sha or self.sha)

    def rewrite(self, entries):
        # An attacker-controlled build can also supply matching hashes. File
        # safety must therefore be checked independently of digest agreement.
        with warnings.catch_warnings(), zipfile.ZipFile(self.input / artifact.ARCHIVE, 'w') as bundle:
            warnings.simplefilter('ignore', UserWarning)
            for name, data, mode in entries:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(entry, data)
        self.sha = hashlib.sha256((self.input / artifact.ARCHIVE).read_bytes()).hexdigest()
        (self.input / 'manifest.json').write_text(json.dumps(dict(self.identity, sha256=self.sha)))

    def test_valid_artifact_preserves_bytes_and_executable_permissions(self):
        app = self.unpack()
        for name, permissions in artifact.FILES.items():
            path = app.parent / name
            self.assertEqual(path.read_bytes(), self.data[name])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), permissions)
        with self.assertRaisesRegex(ValueError, 'already exist'):
            self.unpack()

    def test_tampering_or_other_repository_commit_run_version_is_rejected(self):
        for field, value in [('repository', 'other/repo'), ('commit', 'b' * 40),
                             ('run_id', '124'), ('version', '0.2.0')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity'):
                self.unpack(dict(self.identity, **{field: value}))
        archive = self.input / artifact.ARCHIVE
        archive.write_bytes(archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.unpack()
        self.assertFalse(self.destination.exists())

    def test_unexpected_paths_duplicates_links_and_special_files_are_rejected(self):
        regular = [(name, data, stat.S_IFREG | 0o644) for name, data in self.data.items()]
        bad_entries = [
            regular + [('../escape', b'bad', stat.S_IFREG | 0o644)],
            regular + [('/absolute', b'bad', stat.S_IFREG | 0o644)],
            regular + [regular[0]],
            regular + [('TailVault.app/Contents/Resources/key.p8', b'bad', stat.S_IFREG | 0o600)],
            [(name, data, stat.S_IFLNK | 0o777) for name, data in self.data.items()],
            [(name, data, stat.S_IFIFO | 0o600) for name, data in self.data.items()],
        ]
        for entries in bad_entries:
            self.rewrite(entries)
            with self.assertRaises(ValueError):
                self.unpack()
            self.assertFalse(self.destination.exists())

    def test_compressed_size_and_expanded_size_are_bounded(self):
        with patch.object(artifact, 'LIMIT', 20), self.assertRaises(ValueError):
            self.unpack()
        entries = [(name, b'0' * 100000 if name.endswith('/TailVault') else data,
                    stat.S_IFREG | 0o644) for name, data in self.data.items()]
        self.rewrite(entries)
        self.assertLess((self.input / artifact.ARCHIVE).stat().st_size, 4096)
        with patch.object(artifact, 'LIMIT', 4096), self.assertRaisesRegex(ValueError, 'size'):
            self.unpack()
        self.assertFalse(self.destination.exists())

    def test_bundle_identity_and_executable_path_cannot_be_substituted(self):
        for key, value in [('CFBundleExecutable', '../../private-key'),
                           ('CFBundleIdentifier', 'other.app'), ('CFBundleVersion', '2.0.0'),
                           ('LSMinimumSystemVersion', '26.0')]:
            data = dict(self.data)
            data['TailVault.app/Contents/Info.plist'] = plistlib.dumps(dict(self.info, **{key: value}))
            self.rewrite([(name, value, stat.S_IFREG | 0o644) for name, value in data.items()])
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'metadata'):
                self.unpack()

    def test_unsigned_app_cannot_smuggle_extra_files_or_links(self):
        extra = self.app / 'Contents/extra'
        extra.write_bytes(b'not an app resource')
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            artifact.package(self.app, self.root / 'other', self.identity)
        extra.unlink()
        extra.symlink_to(self.app / 'Contents/Info.plist')
        with self.assertRaisesRegex(ValueError, 'links'):
            artifact.package(self.app, self.root / 'other', self.identity)

    def test_only_version_tags_and_manual_main_builds_can_select_versions(self):
        self.assertEqual(artifact.release_version('push', 'refs/tags/v0.1.0-rc.1', '0.0.0'), '0.1.0')
        self.assertEqual(artifact.release_version('workflow_dispatch', 'refs/heads/main', '0.1.0'), '0.1.0')
        for event, ref in [('workflow_dispatch', 'refs/heads/topic'), ('pull_request', 'refs/heads/main'),
                           ('push', 'refs/tags/v01.2.3'), ('push', 'refs/tags/v0.1.0-rc.0')]:
            with self.subTest(event=event, ref=ref), self.assertRaises(ValueError):
                artifact.release_version(event, ref, '0.1.0')


class WorkflowIsolationTests(unittest.TestCase):
    def test_signer_only_handles_artifacts_and_deletes_keys_before_upload(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        signer = workflow.split('\n  sign:\n', 1)[1].split('\n  publish:\n', 1)[0]
        for prohibited in ('ci-release.sh', 'npm ', 'npx ', 'go run ', 'go build ', 'make ', 'tests/'):
            self.assertNotIn(prohibited, signer)
        self.assertIn('artifact-ids: ${{ needs.validate.outputs.artifact_id }}', signer)
        self.assertLess(signer.index('release-artifact.py unpack'), signer.index('secrets.CODESIGN_PRIVATE_KEY_BASE64'))
        self.assertLess(signer.index('prepare-github-signing.py --cleanup'), signer.index('release-artifact.py finalize'))
        self.assertLess(signer.index('prepare-github-signing.py --cleanup'), signer.index('actions/upload-artifact@'))
        self.assertIn('create-keychain: false', signer)
        self.assertIn('sparse-checkout-cone-mode: false', signer)

    def test_test_driver_refuses_signing_credentials_before_installing_tools(self):
        import os
        import subprocess
        result = subprocess.run(['/bin/bash', 'scripts/ci-release.sh'], cwd=ROOT,
                                env=dict(os.environ, KEYCHAIN_PASSWORD='synthetic-only'),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('must not run with signing credentials', result.stderr)
