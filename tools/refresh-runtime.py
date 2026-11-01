#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,sys
root=Path(sys.argv[1]);manifest=json.loads((root/'integrity.json').read_text())
for name,expected in manifest['files'].items():
    member=root/name
    if member.is_symlink() or not member.is_file():raise ValueError('Missing or symbolic runtime member: '+name)
    actual=hashlib.sha256(member.read_bytes()).hexdigest()
    if name=='nfqws2':manifest['files'][name]=actual
    elif actual!=expected:raise ValueError('Pinned runtime member changed: '+name)
(root/'integrity.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Native runtime manifest updated')
