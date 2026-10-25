#!/usr/bin/env python3
"""Fill the existing QA login from stdin, without submitting or exposing it."""
import argparse
import json
import re
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--session', required=True)
parser.add_argument('--namespace', required=True)
args = parser.parse_args()
if not all(re.fullmatch(r'[a-zA-Z0-9_-]{1,24}', value) for value in (args.session, args.namespace)):
    sys.exit('Invalid browser identity')
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
command = ['/home/roomhacker/.npm-global/bin/agent-browser', '--session', args.session,
           '--namespace', args.namespace, '--auto-connect', 'false', '--headed', 'false',
           '--idle-timeout', '300000', 'eval', '--stdin']
try:
    result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=30)
except (subprocess.TimeoutExpired, OSError):
    sys.exit('Browser fill outcome unknown; inspect this session before continuing')
if result.returncode or result.stdout.strip() != '"qa_credentials_filled"':
    sys.exit('Browser fill not confirmed; inspect this session before continuing')
print('QA credentials filled; submit once using the visible login button. No login submitted by this helper.')
