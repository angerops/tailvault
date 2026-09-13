#!/usr/bin/env python3
"""Materialize release credentials only in a GitHub runner's temporary directory."""
import base64
import binascii
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

REQUIRED = (
    'CODESIGN_IDENTITY', 'CODESIGN_CERTIFICATE_BASE64', 'CODESIGN_PRIVATE_KEY_BASE64',
    'NOTARY_KEY_BASE64', 'NOTARY_KEY_ID', 'NOTARY_ISSUER_ID',
    'RUNNER_TEMP', 'GITHUB_ENV',
)


def decode_file(name, value):
    try:
        data = base64.b64decode(''.join(value.split()), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(name + ' must contain a base64-encoded file') from None
    if not data:
        raise ValueError(name + ' must contain a nonempty file')
    return data


def private_file(path, data=b''):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as destination:
        destination.write(data)


def package_certificate(directory, certificate, private_key, password, key_password):
    """Use stock OpenSSL to parse the inputs and verify the certificate/key pair."""
    private_file(directory / 'certificate.input', certificate)
    private_file(directory / 'private-key.input', private_key)
    for name in ('certificate.pem', 'private-key.pem', 'signing.p12'):
        private_file(directory / name)
    child_env = dict(os.environ, KEYCHAIN_PASSWORD=password,
                     CODESIGN_PRIVATE_KEY_PASSWORD=key_password)
    commands = (
        ('x509', '-inform', 'PEM' if certificate.lstrip().startswith(b'-----BEGIN') else 'DER',
         '-in', 'certificate.input', '-out', 'certificate.pem'),
        ('pkey', '-inform', 'PEM' if private_key.lstrip().startswith(b'-----BEGIN') else 'DER',
         '-in', 'private-key.input', '-passin', 'env:CODESIGN_PRIVATE_KEY_PASSWORD',
         '-out', 'private-key.pem'),
        ('pkcs12', '-export', '-in', 'certificate.pem', '-inkey', 'private-key.pem',
         '-out', 'signing.p12', '-passout', 'env:KEYCHAIN_PASSWORD',
         '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1'),
    )
    for arguments in commands:
        result = subprocess.run(['/usr/bin/openssl', *arguments], cwd=directory,
                                env=child_env, capture_output=True)
        if result.returncode:
            raise ValueError('Unable to package signing credentials: check the certificate, '
                             'matching private key, and CODESIGN_PRIVATE_KEY_PASSWORD')
    for name in ('certificate.input', 'private-key.input', 'certificate.pem', 'private-key.pem'):
        (directory / name).unlink()


def prepare(environ):
    missing = [name for name in REQUIRED if not environ.get(name, '').strip()]
    if missing:
        raise ValueError('Missing GitHub signing settings: ' + ', '.join(missing))
    if not environ['CODESIGN_IDENTITY'].startswith('Developer ID Application: '):
        raise ValueError('CODESIGN_IDENTITY must select a Developer ID Application certificate')
    if not re.fullmatch(r'[A-Z0-9]{10}', environ['NOTARY_KEY_ID']):
        raise ValueError('NOTARY_KEY_ID must be the App Store Connect API key ID')
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', environ['NOTARY_ISSUER_ID']):
        raise ValueError('NOTARY_ISSUER_ID must be the App Store Connect issuer UUID')

    # Decode all files before writing any; diagnostics never include values.
    certificate = decode_file('CODESIGN_CERTIFICATE_BASE64', environ['CODESIGN_CERTIFICATE_BASE64'])
    private_key = decode_file('CODESIGN_PRIVATE_KEY_BASE64', environ['CODESIGN_PRIVATE_KEY_BASE64'])
    api_key = decode_file('NOTARY_KEY_BASE64', environ['NOTARY_KEY_BASE64'])
    if not (api_key.strip().startswith(b'-----BEGIN PRIVATE KEY-----')
            and api_key.strip().endswith(b'-----END PRIVATE KEY-----')):
        raise ValueError('NOTARY_KEY_BASE64 must encode the App Store Connect .p8 PEM file')

    directory = Path(environ['RUNNER_TEMP']) / 'tailvault-signing-inputs'
    directory.mkdir(mode=0o700)
    try:
        # The PKCS12 container and keychain exist only for this job.
        password = secrets.token_urlsafe(32)
        package_certificate(directory, certificate, private_key, password,
                            environ.get('CODESIGN_PRIVATE_KEY_PASSWORD', ''))
        private_file(directory / 'notary.p8', api_key)
        print('::add-mask::' + password)
        with open(environ['GITHUB_ENV'], 'a', encoding='utf-8') as destination:
            destination.write('KEYCHAIN_PASSWORD=' + password + '\n')
    except BaseException:
        shutil.rmtree(directory)
        raise
    return directory


def cleanup(environ):
    """Remove only this job's credential files/keychain before artifact upload."""
    root = Path(environ['RUNNER_TEMP'])
    keychain = root / 'tailvault-signing.keychain'
    try:
        if keychain.exists():
            result = subprocess.run(['/usr/bin/security', 'delete-keychain', str(keychain)],
                                    capture_output=True)
            if result.returncode:
                raise ValueError('Unable to remove the temporary signing keychain')
    finally:
        directory = root / 'tailvault-signing-inputs'
        if directory.exists():
            shutil.rmtree(directory)
        with open(environ['GITHUB_ENV'], 'a', encoding='utf-8') as destination:
            destination.write('KEYCHAIN_PASSWORD=\n')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--cleanup']:
            cleanup(os.environ)
        elif len(sys.argv) == 1:
            prepare(os.environ)
        else:
            raise ValueError('Usage: prepare-github-signing.py [--cleanup]')
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
