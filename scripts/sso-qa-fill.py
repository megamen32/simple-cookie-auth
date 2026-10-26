#!/usr/bin/env python3
"""Fill the existing QA login from stdin, without submitting or exposing it."""
import argparse
import json
import re
import subprocess
import sys

def build_browser_command(session, namespace, idle_timeout):
    return ['/home/roomhacker/.npm-global/bin/agent-browser', '--session', session,
            '--namespace', namespace, '--auto-connect', 'false', '--headed', 'false',
            '--idle-timeout', idle_timeout, 'eval', '--stdin']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument(
        '--idle-timeout', default='300000',
        help='agent-browser daemon idle timeout; keep identical across every session command (default: 300000 ms)',
    )
    args = parser.parse_args()
    if not all(re.fullmatch(r'[a-zA-Z0-9_-]{1,24}', value) for value in (args.session, args.namespace)):
        sys.exit('Invalid browser identity')
    if not re.fullmatch(r'[0-9]+', args.idle_timeout):
        sys.exit('Invalid browser idle timeout')
    try:
        secret = sys.stdin.buffer.read(65537).decode('utf-8').rstrip('\r\n')
    except UnicodeDecodeError:
        sys.exit('Invalid credential encoding')
    if not secret or len(secret.encode()) > 65536:
        sys.exit('Invalid credential input')
    # Only the supported browser stdin seam receives the script. Never print it,
    # browser stderr, or the credential; these can contain page/action diagnostics.
    script = '''(() => {
if (location.origin !== 'https://auth.bezrabotnyi.com' || location.pathname !== '/login') return 'wrong_page';
const u=document.querySelector('input[name=username]');
const p=document.querySelector('input[name=password][type=password]');
if (!u || !p) return 'missing_form';
u.value='testlogin';
p.value=PASSWORD;
u.dispatchEvent(new Event('input',{bubbles:true}));
p.dispatchEvent(new Event('input',{bubbles:true}));
return 'qa_credentials_filled';
})()'''.replace('PASSWORD', json.dumps(secret))
    command = build_browser_command(args.session, args.namespace, args.idle_timeout)
    try:
        result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        sys.exit('Browser fill outcome unknown; inspect this session before continuing')
    if result.returncode or result.stdout.strip() != '"qa_credentials_filled"':
        sys.exit('Browser fill not confirmed; inspect this session before continuing')
    print('QA credentials filled; submit once using the visible login button. No login submitted by this helper.')


if __name__ == '__main__':
    main()
