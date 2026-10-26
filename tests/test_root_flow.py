# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline tests only. All HTTP traffic is loopback; no TV is contacted."""
import base64
import contextlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import root_flow as flow

TEST_SHELL = os.environ.get('LG_ROOT_TEST_SHELL') or shutil.which('sh')


def fixture_environment(binaries, **extra):
    path = binaries.as_posix()
    if os.name == 'nt':
        # Git Bash receives a POSIX PATH; a semicolon-prefixed Windows PATH
        # would silently choose the host id/curl instead of fixture programs.
        path = '/' + path[0].lower() + path[2:]
        path += ':/usr/bin:/bin'
    else:
        path += os.pathsep + os.environ['PATH']
    return {**os.environ, 'PATH': path, **extra}


def public_key():
    algorithm = b'ssh-ed25519'
    wire = struct.pack('!I', len(algorithm)) + algorithm + struct.pack('!I', 32) + bytes(32)
    return 'ssh-ed25519 ' + base64.b64encode(wire).decode()


class BuildTests(unittest.TestCase):
    def args(self, *extra):
        return flow.parser().parse_args(['--tv', '192.0.2.10', '--local-ip', '192.0.2.20', *extra])

    def test_probe_is_default_and_never_targets_boot_cache(self):
        run = flow.prepare(self.args())
        self.assertEqual(run.mode, 'probe')
        self.assertRegex(run.filename, r'^lg-root-probe-[0-9a-f]{16}\.txt$')
        self.assertFalse(run.download_request['appendTargetFile'])
        self.assertEqual(run.download_request['targetDir'], '/mnt/lg/cmn_data/var/cache')
        self.assertNotIn(b'#!/bin/sh', run.payload())

    def test_boot_modes_require_acknowledgement_and_ssh_inputs(self):
        for mode in ('stage', 'ssh'):
            with self.assertRaisesRegex(ValueError, 'acknowledge'):
                flow.prepare(self.args('--mode', mode))
        with self.assertRaisesRegex(ValueError, 'ssh-pubkey'):
            flow.prepare(self.args('--mode', 'ssh', '--acknowledge-cache-overwrite'))

    def test_private_or_malformed_key_never_becomes_shell_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public-key'
            for value in ['-----BEGIN OPENSSH PRIVATE KEY-----', 'ssh-ed25519 bad!',
                          public_key() + '\n' + public_key(), 'ssh-rsa AAAA']:
                path.write_text(value, encoding='ascii')
                with self.assertRaises(ValueError):
                    flow.read_public_key(path)
            path.write_text(public_key() + ' user-comment', encoding='ascii')
            self.assertEqual(flow.read_public_key(path), public_key())

    def test_ssh_validates_binary_and_supplied_key_without_executing(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'public-key'
            binary = Path(directory) / 'dropbear'
            key.write_text(public_key(), encoding='ascii')
            binary.write_bytes(b'not-an-ELF')
            args = self.args('--mode', 'ssh', '--acknowledge-cache-overwrite',
                             '--ssh-pubkey', str(key), '--dropbear', str(binary))
            with self.assertRaisesRegex(ValueError, 'ELF'):
                flow.prepare(args)
            binary.write_bytes(b'\x7fELFoffline-test-fixture')
            run = flow.prepare(args)
            payload = run.payload().decode()
            self.assertIn(' -R -s -p ', payload)
            self.assertIn(public_key(), payload)
            self.assertNotIn('telnetd', payload)
            self.assertNotIn('root-agent/command', payload)

    def test_payload_and_page_keep_exact_successful_download_parameters(self):
        run = flow.prepare(self.args('--mode', 'stage', '--acknowledge-cache-overwrite'))
        request = run.download_request
        self.assertEqual(request['targetFilename'], 'volatile.cache')
        self.assertEqual(request['appendTargetFile'], False)
        self.assertIn(run.prefix, request['target'])
        page = run.page().decode()
        self.assertIn('com.webos.service.downloadmanager/download', page)
        self.assertNotIn('{{', run.payload().decode())
        self.assertNotIn('__REQUEST__', page)
        self.assertEqual(len(run.token), 64)
        self.assertNotEqual(run.token, flow.Run(run.tv, run.local_ip, run.port).token)

    def test_dry_run_does_not_open_network_or_write_pairing_key(self):
        output = io.StringIO()
        with (patch.object(flow, 'ThreadingHTTPServer', side_effect=AssertionError('network forbidden')),
              patch.object(flow.WebSocket, 'connect', side_effect=AssertionError('TV forbidden'))):
            with contextlib.redirect_stdout(output):
                self.assertEqual(flow.main(['--tv', '192.0.2.10', '--local-ip', '192.0.2.20', '--dry-run']), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result['dryRun'])
        self.assertNotIn('token', result)

    def test_probe_acceptance_and_root_proof_have_separate_completion_rules(self):
        run = flow.Run('192.0.2.10', '192.0.2.20', 8081, mode='stage')
        with contextlib.redirect_stdout(io.StringIO()):
            run.accept_report('report', b'{"kind":"DOWNLOAD_ACCEPTED","data":"private raw reply"}')
            self.assertFalse(run.done.is_set())
            self.assertEqual(run.events, [{'kind': 'DOWNLOAD_ACCEPTED'}])
            run.accept_report('result', b'BOOT_ROOT_OK uid=0(root)')
        self.assertTrue(run.done.is_set())
        self.assertEqual(run.callback_result, 'BOOT_ROOT_OK uid=0(root)')

    def test_ssh_requires_process_result_after_root_proof(self):
        run = flow.Run('192.0.2.10', '192.0.2.20', 8081, mode='ssh')
        with contextlib.redirect_stdout(io.StringIO()):
            run.accept_report('result', b'BOOT_ROOT_OK uid=0(root)')
            self.assertFalse(run.done.is_set())
            run.accept_report('result', b'SSH_PROCESS_STARTED port=2222')
        self.assertTrue(run.done.is_set())

    def test_launcher_uses_historically_successful_tinybrowser_entry(self):
        run = flow.Run('192.0.2.10', '192.0.2.20', 8081)
        run.done.set()
        run.callback_result = 'DOWNLOAD_ACCEPTED'
        client = unittest.mock.Mock()
        client.register.return_value = 'fixture-pairing-value'
        client.request.return_value = {'payload': {'returnValue': True}}
        server = unittest.mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'pairing-file'
            with (patch.object(flow, 'Run', return_value=run),
                  patch.object(flow, 'ThreadingHTTPServer', return_value=server),
                  patch.object(flow.WebSocket, 'connect', return_value=object()),
                  patch.object(flow, 'SSAPClient', return_value=client),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(flow.main(['--tv', run.tv, '--local-ip', run.local_ip,
                                            '--pair', '--key-file', str(key)]), 0)
            self.assertEqual(key.read_text(), 'fixture-pairing-value')
        client.request.assert_called_once_with('ssap://system.launcher/launch', {
            'id': 'com.webos.app.tinybrowser', 'params': {'contentTarget': run.url('page')}})


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.run_state = flow.Run('127.0.0.1', '127.0.0.1', 0)
        self.server = flow.ThreadingHTTPServer(('127.0.0.1', 0), flow.make_handler(self.run_state))
        self.run_state.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_routes_require_token_exact_peer_and_only_known_endpoints(self):
        self.assertEqual(self.request('GET', '/run/wrong/page')[0], 403)
        self.assertEqual(self.request('GET', self.run_state.prefix + '/payload')[0], 200)
        self.assertEqual(self.request('GET', self.run_state.prefix + '/../../../etc/passwd')[0], 403)
        self.assertEqual(self.request('GET', self.run_state.prefix + '/dropbear')[0], 404)
        self.run_state.tv = '192.0.2.10'
        self.assertEqual(self.request('GET', self.run_state.prefix + '/page')[0], 403)

    def test_callback_rejects_bad_json_large_body_and_unknown_messages(self):
        prefix = self.run_state.prefix
        self.assertEqual(self.request('POST', prefix + '/report', b'not-json')[0], 400)
        self.assertEqual(self.request('POST', prefix + '/result', b'arbitrary command')[0], 400)
        self.assertEqual(self.request('POST', prefix + '/result', b'x' * (flow.MAX_REPORT + 1))[0], 413)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.request('POST', prefix + '/report', b'{"kind":"DOWNLOAD_ACCEPTED"}')[0], 204)
        self.assertTrue(self.run_state.done.is_set())


@unittest.skipUnless(TEST_SHELL, 'POSIX shell fixture needs sh or an explicit LG_ROOT_TEST_SHELL')
class BootFixtureTests(unittest.TestCase):
    def run_fixture(self, restore=None, mismatch=False, corrupt_restore=False, new_cache_during_fetch=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / 'cache'
            home = root / 'home'
            binaries = root / 'bin'
            cache.mkdir()
            home.mkdir()
            binaries.mkdir()
            run = flow.Run('192.0.2.10', '192.0.2.20', 8081, mode='stage', restore=restore)
            script = run.payload(cache_dir=cache.as_posix(), home_dir=home.as_posix())
            cache_file = cache / 'volatile.cache'
            cache_file.write_bytes(script if not mismatch else b'newer unrelated stage\n')
            executable = root / 'boot-stage.sh'
            executable.write_bytes(script)
            original = root / 'original'
            original.write_bytes(b'corrupt-backup' if corrupt_restore else restore or b'')
            for name, content in {
                'id': "#!/bin/sh\nprintf '0\\n'\n",
                'curl': '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; cp "$FIXTURE_ORIGINAL" "$1"; if [ "$FIXTURE_RACE" = 1 ]; then printf "newer-stage\\n" > "$FIXTURE_CACHE"; fi; exit 0; fi; shift; done\nexit 0\n',
            }.items():
                path = binaries / name
                path.write_text(content, newline='\n')
                path.chmod(0o755)
            environment = fixture_environment(binaries, FIXTURE_ORIGINAL=original.as_posix(),
                                              FIXTURE_RACE='1' if new_cache_during_fetch else '0',
                                              FIXTURE_CACHE=cache_file.as_posix())
            result = subprocess.run([TEST_SHELL, str(executable)], env=environment, timeout=3, capture_output=True)
            return result.returncode, cache_file.read_bytes() if cache_file.exists() else None, (
                cache / ('lg-root-proof-' + run.run_id)).exists(), (
                cache / ('volatile.cache.disabled-' + run.run_id)).exists()

    def test_boot_stage_removes_only_own_cache_and_leaves_uid_marker(self):
        status, cache, proof, isolated = self.run_fixture()
        self.assertEqual(status, 0)
        self.assertIsNone(cache)
        self.assertTrue(proof)
        self.assertFalse(isolated)

    def test_supplied_original_is_hash_checked_and_restored(self):
        original = b'#!/bin/sh\necho original-cache\n'
        status, cache, proof, isolated = self.run_fixture(restore=original)
        self.assertEqual(status, 0)
        self.assertEqual(cache, original)
        self.assertTrue(proof)
        self.assertFalse(isolated)

    def test_another_run_cache_is_never_removed(self):
        status, cache, proof, isolated = self.run_fixture(mismatch=True)
        self.assertEqual(status, 1)
        self.assertEqual(cache, b'newer unrelated stage\n')
        self.assertFalse(proof)
        self.assertFalse(isolated)

    def test_restore_hash_failure_isolates_stage_and_never_claims_success(self):
        status, cache, proof, isolated = self.run_fixture(restore=b'original', corrupt_restore=True)
        self.assertEqual(status, 1)
        self.assertIsNone(cache)
        self.assertTrue(isolated)
        self.assertFalse(proof)

    def test_restore_does_not_overwrite_cache_created_during_download(self):
        status, cache, proof, isolated = self.run_fixture(restore=b'original', new_cache_during_fetch=True)
        self.assertEqual(status, 1)
        self.assertEqual(cache, b'newer-stage\n')
        self.assertTrue(isolated)
        self.assertFalse(proof)

    def test_ssh_adds_a_separate_key_line_and_preserves_existing_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache, home, binaries = root / 'cache', root / 'home', root / 'bin'
            for path in [cache, home / '.ssh', binaries]:
                path.mkdir(parents=True)
            keys = home / '.ssh/authorized_keys'
            keys.write_text('existing-key-without-newline')
            stub = b'#!/bin/sh\nprintf "%s\\n" "$*" > "$FIXTURE_DAEMON_ARGS"\nexit 0\n'
            binary_source = root / 'binary-source'
            binary_source.write_bytes(stub)
            run = flow.Run('192.0.2.10', '192.0.2.20', 8081, mode='ssh',
                           public_key=public_key(), dropbear=stub)
            stage = run.payload(cache_dir=cache.as_posix(), home_dir=home.as_posix(),
                                compat_ssh_dir=(root / 'compat').as_posix())
            (cache / 'volatile.cache').write_bytes(stage)
            script = root / 'boot-stage.sh'
            script.write_bytes(stage)
            mocks = {
                'id': "#!/bin/sh\nprintf '0\\n'\n",
                'curl': '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; cp "$FIXTURE_BINARY" "$1"; exit 0; fi; shift; done\nexit 0\n',
            }
            for name, content in mocks.items():
                command = binaries / name
                command.write_text(content, newline='\n')
                command.chmod(0o755)
            daemon_args = root / 'daemon-args'
            environment = fixture_environment(binaries, FIXTURE_BINARY=binary_source.as_posix(),
                                              FIXTURE_DAEMON_ARGS=daemon_args.as_posix())
            result = subprocess.run([TEST_SHELL, str(script)], env=environment, timeout=3, capture_output=True)
            deadline = time.monotonic() + 3
            while not daemon_args.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(daemon_args.exists())
            self.assertEqual(keys.read_text().splitlines(), ['existing-key-without-newline', public_key()])
            self.assertIn('-R -s -p 2222', daemon_args.read_text())


if __name__ == '__main__':
    unittest.main()
