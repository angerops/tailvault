"""Credential staging boundaries; no real certificates or credentials are used."""
import base64
from contextlib import redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'prepare_github_signing', Path(__file__).resolve().parents[1] / 'scripts/prepare-github-signing.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class SigningInputsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        for suffix in ('', '-other'):
            subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                            '-nodes', '-keyout', str(fixture / ('key' + suffix + '.pem')),
                            '-out', str(fixture / ('cert' + suffix + '.pem')),
                            '-subj', '/CN=TailVault Signing Fixture', '-days', '1'],
                           check=True, capture_output=True)
        cls.certificate = (fixture / 'cert.pem').read_bytes()
        cls.private_key = (fixture / 'key.pem').read_bytes()
        cls.other_key = (fixture / 'key-other.pem').read_bytes()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = b'-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----\n'
        self.env = dict(
            CODESIGN_IDENTITY='Developer ID Application: Fixture (EXAMPLE123)',
            CODESIGN_CERTIFICATE_BASE64=base64.b64encode(self.certificate).decode(),
            CODESIGN_PRIVATE_KEY_BASE64=base64.b64encode(self.private_key).decode(),
            NOTARY_KEY_BASE64=base64.b64encode(self.key).decode(),
            NOTARY_KEY_ID='EXAMPLE123',
            NOTARY_ISSUER_ID='12345678-1234-1234-1234-123456789abc',
            RUNNER_TEMP=str(self.root), GITHUB_ENV=str(self.root / 'github-env'),
        )

    def test_missing_or_malformed_inputs_never_write_credentials_or_report_values(self):
        mutations = [{name: ''} for name in signing.REQUIRED]
        mutations += [dict(CODESIGN_CERTIFICATE_BASE64='sensitive-invalid-base64'),
                      dict(CODESIGN_PRIVATE_KEY_BASE64='sensitive-invalid-base64'),
                      dict(NOTARY_KEY_BASE64='sensitive-invalid-base64'),
                      dict(NOTARY_KEY_BASE64=base64.b64encode(b'not a PEM').decode()),
                      dict(CODESIGN_IDENTITY='Apple Distribution: Fixture'),
                      dict(NOTARY_KEY_ID='sensitive-invalid-key-id'),
                      dict(NOTARY_ISSUER_ID='sensitive-invalid-issuer')]
        for mutation in mutations:
            with self.subTest(fields=list(mutation)), self.assertRaises(ValueError) as raised:
                signing.prepare(dict(self.env, **mutation))
            self.assertNotIn('sensitive-', str(raised.exception))
            self.assertEqual(list(self.root.iterdir()), [])

    def test_materialized_files_stay_private_under_a_permissive_umask(self):
        output = io.StringIO()
        previous_umask = os.umask(0)
        try:
            with redirect_stdout(output):
                directory = signing.prepare(self.env)
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual({path.name for path in directory.iterdir()}, {'signing.p12', 'notary.p8'})
        self.assertEqual((directory / 'notary.p8').read_bytes(), self.key)
        for filename in ('signing.p12', 'notary.p8'):
            path = directory / filename
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for name in ('CODESIGN_CERTIFICATE_BASE64', 'CODESIGN_PRIVATE_KEY_BASE64', 'NOTARY_KEY_BASE64'):
            self.assertNotIn(self.env[name], output.getvalue())
            self.assertNotIn(self.env[name], (self.root / 'github-env').read_text())
        self.assertNotIn('synthetic-key', output.getvalue())
        generated = (self.root / 'github-env').read_text().split('=', 1)[1].strip()
        self.assertGreaterEqual(len(generated), 40)
        self.assertIn('::add-mask::' + generated, output.getvalue())
        subprocess.run(['/usr/bin/openssl', 'pkcs12', '-in', str(directory / 'signing.p12'),
                        '-passin', 'env:FIXTURE_IMPORT_PASSWORD', '-noout'],
                       env=dict(os.environ, FIXTURE_IMPORT_PASSWORD=generated),
                       check=True, capture_output=True)

    def test_mismatched_certificate_and_key_fail_and_remove_inputs(self):
        self.env['CODESIGN_PRIVATE_KEY_BASE64'] = base64.b64encode(self.other_key).decode()
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'matching private key'):
            signing.prepare(self.env)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_der_certificate_and_private_key_can_be_packaged(self):
        for command, original, name in (
                ('x509', self.certificate, 'CODESIGN_CERTIFICATE_BASE64'),
                ('pkey', self.private_key, 'CODESIGN_PRIVATE_KEY_BASE64')):
            der = subprocess.run(['/usr/bin/openssl', command, '-outform', 'DER'],
                                 input=original, capture_output=True, check=True).stdout
            self.env[name] = base64.b64encode(der).decode()
        with redirect_stdout(io.StringIO()):
            directory = signing.prepare(self.env)
        self.assertGreater((directory / 'signing.p12').stat().st_size, 0)

    def test_encrypted_private_key_needs_correct_passphrase_without_echoing_it(self):
        passphrase = 'fixture-only-passphrase'
        encrypted = subprocess.run(['/usr/bin/openssl', 'pkey', '-aes-256-cbc',
                                    '-passout', 'env:FIXTURE_KEY_PASSWORD'], input=self.private_key,
                                   env=dict(os.environ, FIXTURE_KEY_PASSWORD=passphrase),
                                   capture_output=True, check=True).stdout
        self.env['CODESIGN_PRIVATE_KEY_BASE64'] = base64.b64encode(encrypted).decode()
        for wrong_password in ('', 'wrong-fixture-passphrase'):
            self.env['CODESIGN_PRIVATE_KEY_PASSWORD'] = wrong_password
            with self.assertRaises(ValueError) as raised:
                signing.prepare(self.env)
            self.assertNotIn('fixture-passphrase', str(raised.exception))
            self.assertEqual(list(self.root.iterdir()), [])
        self.env['CODESIGN_PRIVATE_KEY_PASSWORD'] = passphrase
        output = io.StringIO()
        with redirect_stdout(output):
            signing.prepare(self.env)
        self.assertNotIn(passphrase, output.getvalue())
        self.assertNotIn(passphrase, (self.root / 'github-env').read_text())

    def test_environment_write_failure_removes_partially_prepared_inputs(self):
        self.env['GITHUB_ENV'] = str(self.root)  # A directory cannot receive the output.
        with redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            signing.prepare(self.env)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_input_directory_is_never_overwritten_or_deleted(self):
        directory = self.root / 'tailvault-signing-inputs'
        directory.mkdir()
        (directory / 'existing').write_text('preserve')
        with self.assertRaises(FileExistsError):
            signing.prepare(self.env)
        self.assertEqual((directory / 'existing').read_text(), 'preserve')

    def test_cleanup_deletes_only_this_jobs_keychain_and_private_inputs(self):
        generated = self.root / 'tailvault-signing.keychain'
        generated.write_bytes(b'synthetic keychain')
        unrelated = self.root / 'unrelated.keychain'
        unrelated.write_bytes(b'preserve')
        directory = self.root / 'tailvault-signing-inputs'
        directory.mkdir()
        (directory / 'notary.p8').write_bytes(self.key)
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as run:
            signing.cleanup(self.env)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/security', 'delete-keychain', str(generated)])
        self.assertFalse(directory.exists())
        self.assertEqual(unrelated.read_bytes(), b'preserve')
        self.assertEqual((self.root / 'github-env').read_text(), 'KEYCHAIN_PASSWORD=\n')

    def test_cleanup_failure_still_removes_raw_inputs_and_clears_password(self):
        (self.root / 'tailvault-signing.keychain').write_bytes(b'synthetic')
        directory = self.root / 'tailvault-signing-inputs'
        directory.mkdir()
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1)), self.assertRaises(ValueError):
            signing.cleanup(self.env)
        self.assertFalse(directory.exists())
        self.assertEqual((self.root / 'github-env').read_text(), 'KEYCHAIN_PASSWORD=\n')
