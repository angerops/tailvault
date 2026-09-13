"""Release recovery and package-boundary tests; all artifacts are synthetic."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import urllib.parse


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


publisher = module('release_common')
target = module('check-macos-target')
COMMIT = 'a' * 40
ARCHIVE = 'TailVault-v1.2.3-macos-arm64.zip'


def release_assets(data=b'first signed archive'):
    return {ARCHIVE: data, 'SHA256SUMS': (publisher.digest(data) + '  ' + ARCHIVE + '\n').encode()}


def build(data=b'first signed archive'):
    return {**release_assets(data),
            'notarization.json': json.dumps({'status': 'Accepted', 'id': 'private-submission-id'}).encode()}


class ReleaseAPI:
    def __init__(self):
        self.release = None
        self.bytes = {}
        self.fail_upload = 0
        self.fail_publish = False
        self.uploads = 0

    def request(self, method, path, payload=None, content_type=None):
        if method == 'GET':
            return copy.deepcopy(self.release)
        if method == 'POST' and path == '/releases':
            assert payload['draft'], 'must create draft before uploads'
            self.release = dict(payload, id=1, assets=[])
            return copy.deepcopy(self.release)
        if method == 'PATCH':
            if payload.get('draft') is False:
                assert set(self.bytes) == {ARCHIVE, 'SHA256SUMS'}, 'must be complete before publication'
                if self.fail_publish:
                    raise RuntimeError('injected publication failure')
            self.release.update(payload)
            return copy.deepcopy(self.release)
        if method == 'POST' and '/assets?' in path:
            self.uploads += 1
            if self.uploads == self.fail_upload:
                raise RuntimeError('injected upload failure')
            name = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name'][0]
            assert name not in self.bytes, 'existing assets must never be replaced'
            self.bytes[name] = payload
            asset = dict(name=name, size=len(payload))
            self.release['assets'].append(asset)
            return asset
        raise AssertionError((method, path))

    def release_url(self, tag):
        return 'https://release.example.test/' + tag

    def download(self, asset, tag):
        return self.bytes[asset['name']]


class PublicationTests(unittest.TestCase):
    def publish(self, api, files=None, event='push', commit=COMMIT, ref='refs/tags/v1.2.3'):
        return publisher.publish(api, commit, '1.2.3', event, ref, files or build())

    def test_failure_at_every_upload_resumes_even_after_rebuild(self):
        for failure in (1, 2):
            with self.subTest(failure=failure):
                api = ReleaseAPI()
                api.fail_upload = failure
                with self.assertRaisesRegex(RuntimeError, 'injected'):
                    self.publish(api)
                self.assertTrue(api.release['draft'])
                old_bytes = copy.deepcopy(api.bytes)
                _, resolved = self.publish(api, build(b'rebuilt signed archive'))
                self.assertFalse(api.release['draft'])
                expected = release_assets() if old_bytes else release_assets(b'rebuilt signed archive')
                self.assertEqual(api.bytes, expected)
                self.assertEqual(resolved, expected, 'cask generation must use the published archive, including on retries')
                self.publish(api, build(b'third rebuild'))
                self.assertEqual(api.bytes, expected)

    def test_failed_publication_is_retryable(self):
        api = ReleaseAPI()
        api.fail_publish = True
        with self.assertRaisesRegex(RuntimeError, 'publication failure'):
            self.publish(api)
        self.assertTrue(api.release['draft'])
        api.fail_publish = False
        self.publish(api, build(b'rebuilt'))
        self.assertFalse(api.release['draft'])
        self.assertEqual(api.uploads, 2)

    def test_notarization_evidence_is_never_published(self):
        api = ReleaseAPI()
        files = build()
        _, resolved = self.publish(api, files)
        self.assertEqual(api.bytes, release_assets())
        self.assertEqual(resolved, release_assets())
        self.assertIn('notarization.json', files, 'publisher must preserve caller-owned build evidence')
        body = api.release['body']
        self.assertNotIn('notarization.json', body)
        self.assertNotIn('private-submission-id', body)
        manifest = json.loads(body.split(publisher.MARKER, 1)[1].split(' -->', 1)[0])
        self.assertEqual(set(manifest['files']), {ARCHIVE, 'SHA256SUMS'})

    def test_conflicting_bytes_and_ownership_are_never_replaced(self):
        for mode in ('bytes', 'commit', 'manifest', 'extra'):
            with self.subTest(mode=mode):
                api = ReleaseAPI()
                self.publish(api, event='workflow_dispatch')
                if mode == 'bytes': api.bytes[ARCHIVE] = b'corrupted'
                if mode == 'commit': api.release['target_commitish'] = 'b' * 40
                if mode == 'manifest': api.release['body'] = api.release['body'].replace(COMMIT, 'b' * 40)
                if mode == 'extra': api.release['assets'].append({'name': 'foreign.zip'})
                original = copy.deepcopy(api.bytes)
                with self.assertRaises(RuntimeError):
                    self.publish(api, event='workflow_dispatch')
                self.assertEqual(api.bytes, original)
                self.assertTrue(api.release['draft'])

    def test_manual_stays_draft(self):
        api = ReleaseAPI()
        self.publish(api, event='workflow_dispatch')
        self.publish(api, event='workflow_dispatch')
        self.assertTrue(api.release['draft'])

    def test_candidate_tag_is_marked_as_prerelease(self):
        api = ReleaseAPI()
        self.publish(api, ref='refs/tags/v1.2.3-rc.1')
        self.assertFalse(api.release['draft'])
        self.assertTrue(api.release['prerelease'])
        self.assertEqual(api.release['tag_name'], 'v1.2.3-rc.1')
        self.assertEqual(api.release['target_commitish'], COMMIT)

    def test_invalid_candidate_tags_cannot_create_releases(self):
        for ref in ('refs/tags/v1.2.3-rc.0', 'refs/tags/v1.2.3-rc.01',
                    'refs/tags/v1.2.3-rc.x', 'refs/tags/v1.2.4-rc.1'):
            api = ReleaseAPI()
            with self.assertRaises(RuntimeError):
                self.publish(api, ref=ref)
            self.assertIsNone(api.release)

    def test_candidate_cannot_silently_become_a_stable_release(self):
        api = ReleaseAPI()
        self.publish(api, ref='refs/tags/v1.2.3-rc.1')
        api.release['prerelease'] = False
        original = copy.deepcopy(api.bytes)
        with self.assertRaisesRegex(RuntimeError, 'prerelease status'):
            self.publish(api, ref='refs/tags/v1.2.3-rc.1')
        self.assertEqual(api.bytes, original)

    def test_legacy_partial_public_release_can_resume_only_matching_bytes(self):
        api = ReleaseAPI()
        api.fail_upload = 2
        with self.assertRaises(RuntimeError): self.publish(api)
        api.release['body'] = 'Historical release without manifest'
        api.release['draft'] = False
        with self.assertRaisesRegex(RuntimeError, 'Conflicting'):
            self.publish(api, build(b'different build'))
        self.publish(api)
        self.assertFalse(api.release['draft'])
        self.assertEqual(api.bytes, release_assets())

    def test_unverified_input_never_creates_release(self):
        for mode in ('checksum', 'notary', 'missing-notary', 'malformed-notary', 'notary-array', 'tag', 'version'):
            api = ReleaseAPI()
            files = build()
            if mode == 'checksum': files[ARCHIVE] = b'changed'
            if mode == 'notary': files['notarization.json'] = b'{"status":"Rejected"}'
            if mode == 'missing-notary': del files['notarization.json']
            if mode == 'malformed-notary': files['notarization.json'] = b'not JSON'
            if mode == 'notary-array': files['notarization.json'] = b'[]'
            with self.assertRaises(RuntimeError):
                publisher.publish(api, COMMIT, 'invalid' if mode == 'version' else '1.2.3', 'push',
                                  'refs/tags/v9.9.9' if mode == 'tag' else 'refs/tags/v1.2.3', files)
            self.assertIsNone(api.release)



class TargetTests(unittest.TestCase):
    def test_each_slice_must_match_bundle(self):
        target.check_target('15.0', 'platform MACOS\nminos 15.0\nplatform MACOS\nminos 15.0.0\n')
        for output in ('', 'platform IOS\nminos 15.0\n', 'platform MACOS\nminos 26.0\n',
                       'platform MACOS\nminos 15.0\nplatform MACOS\nminos 13.0\n', 'minos 15.0\n'):
            with self.assertRaises(ValueError): target.check_target('15.0', output)


if __name__ == '__main__':
    unittest.main()
