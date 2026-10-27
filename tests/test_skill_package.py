# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check that the installed skill works without the source checkout or network."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / 'skills' / 'lg-webos-c4-root'


class SkillPackageTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.installed = self.directory / 'installed' / 'lg-webos-c4-root'
        shutil.copytree(SKILL, self.installed,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.local'))
        self.guard = self.directory / 'offline-guard'
        self.guard.mkdir()
        # Python audit events cover both socket construction and DNS. Any
        # accidental network operation makes the subprocess fail immediately.
        (self.guard / 'sitecustomize.py').write_text(
            "import sys\n"
            "def forbid_network(event, arguments):\n"
            "    if event.startswith('socket.'):\n"
            "        raise RuntimeError('network forbidden in skill package tests')\n"
            "sys.addaudithook(forbid_network)\n",
            encoding='utf-8')

    def cli(self, *arguments):
        environment = {**os.environ, 'PYTHONPATH': str(self.guard),
                       'PYTHONDONTWRITEBYTECODE': '1'}
        return subprocess.run(
            [sys.executable, str(self.installed / 'scripts' / 'root_flow.py'), *arguments],
            cwd=self.directory, env=environment, capture_output=True, text=True,
            encoding='utf-8', timeout=20, check=False)

    def assert_dry_run(self, result, mode):
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['dryRun'])
        self.assertEqual(report['mode'], mode)
        self.assertRegex(report['payloadSha256'], r'^[a-f0-9]{64}$')
        self.assertFalse((self.directory / '.local').exists())
        self.assertFalse((self.installed / '.local').exists())
        return report

    def test_subprocess_network_guard_is_active(self):
        result = subprocess.run(
            [sys.executable, '-c', 'import socket; socket.socket()'],
            cwd=self.directory,
            env={**os.environ, 'PYTHONPATH': str(self.guard),
                 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, text=True, encoding='utf-8', timeout=20, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('network forbidden in skill package tests', result.stderr)

    def test_installed_help_probe_and_stage_need_no_checkout_or_network(self):
        help_result = self.cli('--help')
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('--dry-run', help_result.stdout)
        base = ['--tv', '192.0.2.10', '--local-ip', '192.0.2.20', '--dry-run']
        probe = self.assert_dry_run(self.cli(*base), 'probe')
        self.assertRegex(probe['targetFilename'], r'^lg-root-probe-[a-f0-9]{16}\.txt$')
        stage = self.assert_dry_run(
            self.cli(*base, '--mode', 'stage', '--acknowledge-cache-overwrite'), 'stage')
        self.assertEqual(stage['targetFilename'], 'volatile.cache')

    def test_installed_ssh_dry_run_uses_only_supplied_public_key_and_elf(self):
        algorithm = b'ssh-ed25519'
        wire = struct.pack('!I', len(algorithm)) + algorithm + struct.pack('!I', 32) + bytes(32)
        key = self.directory / 'synthetic-test-key.pub'
        key.write_text('ssh-ed25519 ' + base64.b64encode(wire).decode(), encoding='ascii')
        binary = self.directory / 'synthetic-test-elf'
        binary.write_bytes(b'\x7fELFoffline-test-fixture')
        self.assert_dry_run(self.cli(
            '--tv', '192.0.2.10', '--local-ip', '192.0.2.20', '--mode', 'ssh',
            '--acknowledge-cache-overwrite', '--ssh-pubkey', str(key),
            '--dropbear', str(binary), '--dry-run'), 'ssh')

    def test_installed_boot_modes_keep_acknowledgement_guard(self):
        for mode in ('stage', 'ssh'):
            with self.subTest(mode=mode):
                result = self.cli('--tv', '192.0.2.10', '--local-ip', '192.0.2.20',
                                  '--mode', mode, '--dry-run')
                self.assertEqual(result.returncode, 2)
                self.assertIn('requires --acknowledge-cache-overwrite', result.stderr)

    def test_runtime_and_license_are_identical_to_reviewed_canonical_files(self):
        for source, bundled in (
            ('tools/root_flow.py', 'scripts/root_flow.py'),
            ('tools/webos_ssap.py', 'scripts/webos_ssap.py'),
            ('payloads/boot-stage.sh', 'payloads/boot-stage.sh'),
            ('LICENSE', 'LICENSE'),
        ):
            with self.subTest(source=source):
                self.assertEqual((ROOT / source).read_bytes(), (SKILL / bundled).read_bytes())
        for name in ('PROCESS.md', 'RECOVERY.md', 'VERIFICATION.md'):
            expected = (ROOT / 'docs' / name).read_text(encoding='utf-8').replace(
                'tools/root_flow.py', 'scripts/root_flow.py').replace(
                '本仓库的历史成功范围只有 README 所列设备。',
                '历史成功范围见 [验证记录](VERIFICATION.md)。')
            self.assertEqual(expected, (SKILL / 'references' / name).read_text(encoding='utf-8'))
        notice = (ROOT / 'NOTICE.md').read_text(encoding='utf-8').replace(
            'tools/webos_ssap.py', 'scripts/webos_ssap.py')
        self.assertEqual(notice, (SKILL / 'NOTICE.md').read_text(encoding='utf-8'))

    def test_installed_markdown_links_stay_inside_the_self_contained_package(self):
        for document in self.installed.rglob('*.md'):
            for destination in re.findall(r'\]\(([^)]+)\)', document.read_text(encoding='utf-8')):
                destination = destination.split('#', 1)[0]
                if not destination or '://' in destination or destination.startswith('mailto:'):
                    continue
                target = (document.parent / destination).resolve()
                with self.subTest(document=document.name, destination=destination):
                    self.assertTrue(target.is_relative_to(self.installed.resolve()))
                    self.assertTrue(target.is_file(), f'Missing local link: {target}')


if __name__ == '__main__':
    unittest.main()
