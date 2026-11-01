#!/usr/bin/env python3
"""Check documentation links, requested typography and release workflow structure."""
from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.work', 'vendor', 'build', 'dist', '__pycache__', '.venv'}
TEXT = {'.py', '.go', '.md', '.yml', '.yaml', '.sh', '.json', '.txt', '.svg', '.policy', '.desktop'}

def main():
    failures = []
    for path in ROOT.rglob('*'):
        relative = path.relative_to(ROOT)
        if any(part in SKIP for part in relative.parts) or not path.is_file():
            continue
        if path.suffix not in TEXT and path.name not in ('Makefile', 'LICENSE', 'go.mod', '.gitignore', '.gitattributes'):
            continue
        text = path.read_text(encoding='utf-8')
        if any(char in text for char in ('\u2013', '\u2014', '\u2015', '\u2e3a', '\u2e3b')):
            failures.append(str(relative) + ': long dash found')
        if path.suffix == '.md':
            targets = re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', text)
            targets += re.findall(r'(?:src|href)="([^"]+)"', text)
            for target in targets:
                if re.match(r'[a-z]+:', target) or target.startswith('#'):
                    continue
                target = target.split('#', 1)[0]
                if target and not (path.parent / target).exists():
                    failures.append(str(relative) + ': missing link ' + target)
    workflow = yaml.load((ROOT / '.github/workflows/build.yml').read_text(), Loader=yaml.BaseLoader)
    if workflow.get('permissions') != {'contents': 'read'}:
        failures.append('Build workflow must default to contents: read')
    jobs = workflow.get('jobs', {})
    matrix = jobs.get('package', {}).get('strategy', {}).get('matrix', {}).get('include', [])
    if {entry.get('platform') for entry in matrix} != {'ubuntu', 'debian', 'fedora', 'arch'}:
        failures.append('Native matrix must cover all four platforms')
    publisher = jobs.get('release', {})
    if publisher.get('permissions') != {'contents': 'write'} or "github.ref_type == 'tag'" not in publisher.get('if', ''):
        failures.append('Publishing must be tag-only with a separate write permission')
    for job in jobs.values():
        for step in job.get('steps', []):
            if 'uses' in step and not re.fullmatch(r'actions/[\w-]+@[0-9a-f]{40}', step['uses']):
                failures.append('Action is not pinned to a reviewed commit: ' + step['uses'])
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print('Repository typography, documentation links and release workflow checks passed')
    return 0

if __name__ == '__main__':
    sys.exit(main())
