#!/usr/bin/env python3
"""Build native distro packages from one verified, byte-preserving payload."""
from pathlib import Path
import argparse,hashlib,json,os,platform,pwd,re,shutil,subprocess,tarfile,tempfile

ROOT=Path(__file__).resolve().parents[1]
VERSION=re.search(r'const Version = "([^"]+)"',(ROOT/'internal/core/types.go').read_text()).group(1)

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,**kwargs):subprocess.run(args,check=True,**kwargs)
def copy(source,destination,executable=False):
    destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,destination)
    destination.chmod(0o755 if executable else 0o644)

def payload(stage,runtime):
    manifest=json.loads((runtime/'integrity.json').read_text())
    for name,expected in manifest['files'].items():
        file=runtime/name
        if file.is_symlink() or not file.is_file() or digest(file)!=expected:raise ValueError('Runtime integrity failure: '+name)
    for name in ('zarpd','zarpctl'):copy(ROOT/'build'/name,stage/'usr/lib/zarp'/name,True)
    copy(ROOT/'build/zarpctl',stage/'usr/bin/zarpctl',True)
    for module in (ROOT/'desktop').glob('*.py'):copy(module,stage/'usr/lib/zarp/desktop'/module.name,module.name=='zarp.py')
    for folder in ('fonts','lang'):
        for member in (ROOT/'resources'/folder).glob('*'):
            if member.is_file():copy(member,stage/'usr/lib/zarp/resources'/folder/member.name)
    for member in runtime.rglob('*'):
        if member.is_file():copy(member,stage/'usr/lib/zarp/runtime'/member.relative_to(runtime),member.name in ('nfqws2','sing-box','xray'))
    for source,target,executable in [('zarp','usr/bin/zarp',True),('start-service','usr/lib/zarp/start-service',True),('zarp.service','usr/lib/systemd/system/zarp.service',False),('dev.zarp.policy','usr/share/polkit-1/actions/dev.zarp.policy',False),('zarp.desktop','usr/share/applications/zarp.desktop',False)]:copy(ROOT/'packaging'/source,stage/target,executable)
    for target in ('usr/lib/zarp/resources/zarp.svg','usr/share/icons/hicolor/scalable/apps/zarp.svg'):copy(ROOT/'resources/zarp.svg',stage/target)
    copy(ROOT/'LICENSE',stage/'usr/share/doc/zarp/copyright');copy(ROOT/'README.md',stage/'usr/share/doc/zarp/README.md')
    copy(ROOT/'THIRD_PARTY_NOTICES.md',stage/'usr/share/doc/zarp/THIRD_PARTY_NOTICES.md')
    for member in (ROOT/'resources/licenses').glob('*'):copy(member,stage/'usr/share/doc/zarp/licenses'/member.name)
    for folder in [stage,*(p for p in stage.rglob('*') if p.is_dir())]:folder.chmod(0o755)

def tar_payload(stage,target):
    with tarfile.open(target,'w:gz') as archive:
        def normalise(info):info.uid=info.gid=0;info.uname=info.gname='root';return info
        for member in sorted(stage.rglob('*')):archive.add(member,arcname=str(member.relative_to(stage)),recursive=False,filter=normalise)

def build_deb(stage,output,release):
    libc=subprocess.check_output(['getconf','GNU_LIBC_VERSION'],text=True).strip().split()[-1]
    metadata=stage/'DEBIAN';metadata.mkdir()
    (metadata/'control').write_text(f'''Package: zarp
Version: {VERSION}-1+{release}
Section: net
Priority: optional
Architecture: amd64
Installed-Size: {sum(p.stat().st_size for p in stage.rglob('*') if p.is_file())//1024+1}
Maintainer: ZarpVPN
Depends: ca-certificates, nftables, iptables, iproute2, gpgv, apt, pkexec, polkitd, python3, python3-pyside6.qtwidgets, qt6-qpa-plugins, qt6-wayland, fonts-dejavu-core, liblua5.4-0, libnetfilter-queue1, libnfnetlink0, libmnl0, zlib1g, libc6 (>= {libc})
Description: WARP and VPN connections through zapret2
 Native desktop and system service; WARP client is installed separately.
''')
    for name,body in {'postinst':'if [ "$1" = configure ] && [ -d /run/systemd/system ]; then systemctl daemon-reload; fi','prerm':'if [ "$1" = remove ] || [ "$1" = upgrade ]; then if [ -d /run/systemd/system ]; then systemctl stop zarp.service; fi; fi','postrm':'if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi'}.items():
        file=metadata/name;file.write_text('#!/bin/sh\nset -e\n'+body+'\n');file.chmod(0o755)
    package=output/f'zarp_{VERSION}-1+{release}_amd64.deb';run(['dpkg-deb','--root-owner-group','--build',str(stage),str(package)]);return package

def build_rpm(stage,output,work):
    for folder in ('SOURCES','SPECS','BUILD','BUILDROOT','RPMS','SRPMS'):(work/folder).mkdir()
    tar_payload(stage,work/'SOURCES/zarp-payload.tar.gz')
    # RPM must not strip or rewrite binaries covered by the integrity manifest.
    (work/'SPECS/zarp.spec').write_text(f'''%global debug_package %{{nil}}
%global _build_id_links none
%global __os_install_post %{{nil}}
Name: zarp
Version: {VERSION}
Release: 1%{{?dist}}
Summary: WARP and VPN connections through zapret2
License: MIT AND GPL-3.0-or-later AND MPL-2.0 AND OFL-1.1
URL: https://github.com/ZarpVPN/Zarp-Linux
Source0: zarp-payload.tar.gz
BuildArch: x86_64
Requires: python3, python3-pyside6, nftables, iptables-nft, iproute, polkit, gnupg2
Requires: (python3 < 3.14 or python3 >= 3.14.5)
%description
Native desktop and system service. WARP client is installed separately.
%prep
%build
%install
mkdir -p %{{buildroot}}
tar -xf %{{SOURCE0}} -C %{{buildroot}}
%post
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
%preun
if [ "$1" = 0 ] && [ -d /run/systemd/system ]; then systemctl stop zarp.service || :; fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
%files
/usr/bin/zarp
/usr/bin/zarpctl
/usr/lib/zarp
/usr/lib/systemd/system/zarp.service
/usr/share/applications/zarp.desktop
/usr/share/icons/hicolor/scalable/apps/zarp.svg
/usr/share/polkit-1/actions/dev.zarp.policy
/usr/share/doc/zarp
''')
    shutil.copyfile(work/'SPECS/zarp.spec',output/'zarp.spec')
    run(['rpmbuild','--define','_topdir '+str(work),'-bb',str(work/'SPECS/zarp.spec')])
    file=next((work/'RPMS').rglob('*.rpm'));package=output/file.name;shutil.copyfile(file,package);return package

def build_arch(stage,output,work):
    tar_payload(stage,work/'zarp-payload.tar.gz');checksum=digest(work/'zarp-payload.tar.gz')
    recipe=f'''pkgname=zarp
pkgver={VERSION}
pkgrel=1
pkgdesc='WARP and VPN connections through zapret2'
arch=('x86_64')
url='https://github.com/ZarpVPN/Zarp-Linux'
license=('MIT' 'GPL-3.0-or-later' 'MPL-2.0' 'OFL-1.1')
depends=('python' 'pyside6' 'qt6-base' 'nftables' 'iptables' 'iproute2' 'gnupg' 'polkit' 'lua54' 'libnetfilter_queue' 'libmnl' 'zlib' 'ttf-dejavu')
options=('!strip' '!debug')
source=('zarp-payload.tar.gz')
sha256sums=('{checksum}')
package() {{ cp -a "$srcdir/usr" "$pkgdir/"; }}
'''
    (work/'PKGBUILD').write_text(recipe);(output/'PKGBUILD').write_text(recipe)
    if os.geteuid()==0:
        user=pwd.getpwnam('zarpbuild')
        for member in [work,*work.rglob('*')]:os.chown(member,user.pw_uid,user.pw_gid)
        # The parent temporary directory is traversable; build output remains owned by the builder.
        work.parent.chmod(0o755);command=['runuser','-u','zarpbuild','--','makepkg','--force','--noconfirm']
    else:command=['makepkg','--force','--noconfirm']
    run(command,cwd=work);file=next(work.glob('zarp-*.pkg.tar.zst'));package=output/file.name;shutil.copyfile(file,package);return package

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--format',choices=('auto','deb','rpm','arch'),default='auto');parser.add_argument('--runtime',type=Path,default=ROOT/'vendor/runtime');parser.add_argument('--output',type=Path);parser.add_argument('--release');args=parser.parse_args()
    distro=platform.freedesktop_os_release();distro_id=distro['ID'];args.release=args.release or re.sub(r'[^a-z0-9.]','',distro_id+distro.get('VERSION_ID',''))
    if args.format=='auto':
        args.format={'ubuntu':'deb','debian':'deb','fedora':'rpm','arch':'arch'}.get(distro_id)
        if not args.format:parser.error('Unsupported distro; specify --format and native dependencies explicitly')
    args.output=args.output or ROOT/'build/packages'/args.release;args.output.mkdir(parents=True,exist_ok=True)
    if not re.fullmatch(r'[a-z0-9.]+',args.release):parser.error('Invalid release label')
    with tempfile.TemporaryDirectory(prefix='zarp-native-') as directory:
        root=Path(directory);stage=root/'payload';stage.mkdir(mode=0o755);payload(stage,args.runtime)
        if args.format=='deb':package=build_deb(stage,args.output,args.release)
        else:
            work=root/'build';work.mkdir();package=build_rpm(stage,args.output,work) if args.format=='rpm' else build_arch(stage,args.output,work)
    package.with_name(package.name+'.sha256').write_text(digest(package)+'  '+package.name+'\n');print('PACKAGE '+str(package),flush=True)

if __name__=='__main__':main()
