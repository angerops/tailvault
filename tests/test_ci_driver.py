"""Execute CI mode selection without downloads, real credentials, or app builds."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# Only external tools are stand-ins; the CI driver is copied and run unchanged.
TOOL = r'''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

command, args = Path(sys.argv[0]).name, sys.argv[1:]
def record(message):
    with open(os.environ['CI_FIXTURE_LOG'], 'a') as output:
        output.write(message + '\n')

if command == 'curl':
    destination = Path(args[args.index('-o') + 1])
    if destination.name == 'releases.json':
        destination.write_text(json.dumps([{'version': 'go1.26.6', 'stable': True,
            'files': [{'os': 'darwin', 'arch': 'arm64', 'kind': 'archive',
                       'filename': 'fixture-go.tar.gz', 'sha256': '0' * 64}]}]))
    else:
        destination.write_bytes(b'synthetic archive')
elif command == 'shasum':
    sys.stdin.read()
elif command == 'tar':
    root = Path(args[args.index('-C') + 1])
    for relative in ('go/bin', 'node-v22.22.3-darwin-arm64/bin'):
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        for name in ('go', 'node', 'npm', 'npx', 'make'):
            executable = directory / name
            if not executable.exists():
                executable.symlink_to(os.environ['CI_FIXTURE_TOOL'])
elif command in ('go', 'node', 'npm', 'npx'):
    pass
elif command == 'make':
    record('make ' + ' '.join(args))
    if args == ['test', 'check']:
        sys.exit(int(os.environ.get('CI_FIXTURE_FAIL_CHECKS', '0')))
    if args != ['build']:
        sys.exit('Unexpected make invocation')
    Path('bin/TailVault.app').mkdir(parents=True)
    Path('bin/TailVault-macos-arm64.zip').write_bytes(b'synthetic package')
elif command == 'release-artifact.py':
    record(args[0])
    if args[0] == 'version':
        print('0.1.0')
    elif args[0] == 'package':
        destination = Path(args[args.index('--output') + 1])
        destination.mkdir(parents=True)
        (destination / 'TailVault-unsigned.zip').write_bytes(b'synthetic input')
    else:
        sys.exit('Unexpected artifact operation')
else:
    sys.exit('Unexpected tool: ' + command)
'''


class CIDriverTests(unittest.TestCase):
    def run_driver(self, mode=None, **environment):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scripts, helpers, scratch = (root / name for name in ('scripts', 'helpers', 'tmp'))
        for directory in (scripts, helpers, scratch):
            directory.mkdir()
        shutil.copyfile(ROOT / 'scripts/ci-release.sh', scripts / 'ci-release.sh')
        (root / 'go.mod').write_text('module fixture\n\ngo 1.26.6\n')
        tool = helpers / 'fixture-tool.py'
        tool.write_text(TOOL)
        tool.chmod(0o755)
        for name in ('curl', 'shasum', 'tar'):
            (helpers / name).symlink_to(tool)
        (scripts / 'release-artifact.py').symlink_to(tool)
        (scripts / 'build-macos-app.sh').write_text(
            '#!/bin/sh\nset -eu\n'
            'test "$1" = --unsigned\n'
            'printf "unsigned\\n" >> "$CI_FIXTURE_LOG"\n'
            'mkdir -p bin/unsigned/TailVault.app\n')
        log = root / 'calls'
        env = dict(PATH=str(helpers) + ':/usr/bin:/bin:/usr/sbin:/sbin',
                   TMPDIR=str(scratch), CI_FIXTURE_TOOL=str(tool),
                   CI_FIXTURE_LOG=str(log), **environment)
        args = ['/bin/bash', str(scripts / 'ci-release.sh')]
        if mode:
            args.append(mode)
        result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True)
        events = log.read_text().splitlines() if log.exists() else []
        self.assertEqual(list(scratch.iterdir()), [], result.stderr)
        return result, events, root

    def test_checks_only_runs_validation_without_creating_app_outputs(self):
        result, events, root = self.run_driver('--checks-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ['make test check'])
        self.assertFalse((root / 'bin').exists())

    def test_default_still_validates_before_packaging(self):
        result, events, root = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ['make test check', 'make build'])
        self.assertTrue((root / 'bin/TailVault-macos-arm64.zip').is_file())

    def test_release_still_validates_before_building_signing_inputs(self):
        result, events, root = self.run_driver('--release-input')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, ['version', 'make test check', 'unsigned', 'package'])
        self.assertTrue((root / 'bin/signing-input/TailVault-unsigned.zip').is_file())

    def test_failed_checks_prevent_packaging_in_every_mode(self):
        for mode in (None, '--checks-only', '--release-input'):
            with self.subTest(mode=mode):
                result, events, root = self.run_driver(mode, CI_FIXTURE_FAIL_CHECKS='17')
                self.assertEqual(result.returncode, 17, result.stderr)
                expected = ['version'] if mode == '--release-input' else []
                self.assertEqual(events, expected + ['make test check'])
                self.assertFalse((root / 'bin').exists())

    def test_checks_only_keeps_the_signing_credential_guard(self):
        result, events, root = self.run_driver('--checks-only', KEYCHAIN_PASSWORD='synthetic-only')
        self.assertEqual(result.returncode, 2)
        self.assertIn('must not run with signing credentials', result.stderr)
        self.assertEqual(events, [])
        self.assertFalse((root / 'bin').exists())
