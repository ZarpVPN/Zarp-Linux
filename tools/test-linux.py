#!/usr/bin/env python3
"""Test a source tree or installed package without connecting a real VPN."""
import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true')
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--gui-user')
    parser.add_argument('--skip-netns', action='store_true')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/test-results/local')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    desktop = Path('/usr/lib/zarp') if args.installed else ROOT
    daemon = desktop / ('zarpd' if args.installed else 'build/zarpd')
    runtime = (args.runtime or (desktop / 'runtime' if args.installed else ROOT / 'vendor/runtime')).resolve()
    env = os.environ.copy()
    env.update(ZARP_TEST_RUNTIME=str(runtime), ZARP_PROJECT_ROOT=str(ROOT),
               ZARP_DESKTOP_ROOT=str(desktop), ZARP_TEST_DAEMON=str(daemon),
               PYTHONDONTWRITEBYTECODE='1', QT_QPA_PLATFORM='offscreen')
    report = {'platform': platform.freedesktop_os_release(), 'checks': {}, 'remote_vpn': 'not tested', 'started': time.time()}

    def check(name, command, timeout=300, environment=env):
        with (output / (name + '.log')).open('w') as log:
            try:
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
                code = result.returncode
            except (subprocess.TimeoutExpired, OSError) as error:
                log.write(str(error) + '\n')
                code = 124
        report['checks'][name] = {'passed': code == 0, 'exit_code': code}
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(name, 'passed' if code == 0 else 'FAILED', flush=True)
        if code != 0:
            print(name + ' failure details:', flush=True)
            print('\n'.join((output / (name + '.log')).read_text(errors='replace').splitlines()[-60:]), flush=True)
        return code == 0

    check('repository', ['python3', 'tools/check-repo.py'])
    if args.installed:
        check('daemon-version', [str(daemon), '--version'])
        check('native-libraries', ['ldd', str(runtime / 'nfqws2')])
    check('go-race', ['go', 'test', '-race', './internal/...', './cmd/...'])
    check('build-tools', ['python3', '-m', 'unittest', 'discover', '-s', 'tools/tests', '-v'])
    check('compact-quic', ['python3', 'tools/compact-quic-fake.py', '--check'])
    gui_command = ['python3', '-m', 'unittest', 'discover', '-s', str(ROOT / 'desktop/tests'), '-v']
    with tempfile.TemporaryDirectory(prefix='zarp-gui-artifacts-') as gui_directory:
        gui_env = env.copy()
        gui_env['ZARP_TEST_SCREENSHOTS'] = gui_directory
        if os.geteuid() == 0:
            if not args.gui_user:
                parser.error('Root callers must specify an ordinary --gui-user')
            gui_user = pwd.getpwnam(args.gui_user)
            if gui_user.pw_uid == 0:
                parser.error('Root callers must specify an ordinary --gui-user')
            os.chown(gui_directory, gui_user.pw_uid, gui_user.pw_gid)
            gui_command = ['runuser', '-u', args.gui_user, '--', 'env',
                           'QT_QPA_PLATFORM=offscreen', 'PYTHONDONTWRITEBYTECODE=1',
                           'ZARP_TEST_SCREENSHOTS=' + gui_directory,
                           'ZARP_DESKTOP_ROOT=' + str(desktop), 'ZARP_TEST_DAEMON=' + str(daemon), *gui_command]
        check('gui', gui_command, timeout=90, environment=gui_env)
        shutil.copytree(gui_directory, output / 'screenshots', dirs_exist_ok=True)
    if not args.skip_netns:
        if os.geteuid() != 0:
            parser.error('Packet tests require root; use --skip-netns or run the namespace script with sudo')
        check('isolated-packets', ['bash', 'scripts/test-netns.sh'], timeout=150)
    report['passed'] = all(item['passed'] for item in report['checks'].values())
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    summary = '# Linux test results\n\n| Check | Result |\n| --- | --- |\n'
    summary += ''.join(f'| {name} | {"PASS" if item["passed"] else "FAIL"} |\n' for name, item in report['checks'].items())
    (output / 'summary.md').write_text(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as target:
            target.write(summary)
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
