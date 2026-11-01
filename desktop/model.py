from __future__ import annotations
import copy,json,os,re,shlex,tempfile,uuid
from pathlib import Path
from PySide6.QtCore import QLocale

ROOT=Path(__file__).resolve().parents[1]
LANGUAGES=[('en','English'),('ru','Русский'),('es','Español'),('pt','Português'),('zh','中文'),('hi','हिन्दी'),('fr','Français'),('de','Deutsch'),('fa','فارسی')]

class Translation:
    def __init__(self,code='ru'):
        self.code=code;self.tables={}
        for path in (ROOT/'resources/lang').glob('*.txt'):
            table={}
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    key,value=line.split('=',1);table[key.strip()]=value.strip().replace('\\n','\n').replace('Windows','Linux')
            self.tables[path.stem]=table
    def __call__(self,key,*args):
        value=self.tables.get(self.code,{}).get(key,self.tables.get('en',{}).get(key,key))
        try:return value.format(*args)
        except (IndexError,KeyError,ValueError):return value

DEFAULT_PRESETS=[{'id':'lan','name':'','direct':'geoip:private','proxy':'','block':''}]+[{'id':c,'name':'','direct':'geoip:private\ngeoip:'+c,'proxy':'','block':''} for c in ('ru','ir','cn')]
GEO_DEFAULT={kind:'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/'+kind+'.dat' for kind in ('geoip','geosite')}

def profile_uri(profile):
    from urllib.parse import quote,urlencode
    host=profile['host'];host='['+host+']' if ':' in host else host
    params={'type':profile.get('network','tcp'),'security':profile.get('security','tls')}
    for field,key in [('sni','sni'),('path','path'),('hostHeader','host'),('serviceName','serviceName'),('fingerprint','fp'),('flow','flow'),('publicKey','pbk'),('shortID','sid'),('ech','ech'),('mode','mode')]:
        if profile.get(field):params[key]=profile[field]
    if profile.get('alpn'):params['alpn']=','.join(profile['alpn'])
    if profile.get('insecure'):params['insecure']='1'
    if profile.get('obfsPassword'):params.update({'obfs':'salamander','obfs-password':profile['obfsPassword']})
    if profile.get('certificatePins'):params['pcs']=','.join(profile['certificatePins'])
    if profile.get('extra'):params['extra']=json.dumps(profile['extra'],ensure_ascii=False,separators=(',',':'))
    return profile['protocol']+'://'+quote(profile['credential'],safe='')+'@'+host+':'+str(profile['port'])+'?'+urlencode(params)+'#'+quote(profile.get('name',''),safe='')

class Preferences:
    def __init__(self,demo=False):
        base=Path(os.environ.get('ZARP_UI_STATE_HOME',str(Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/('zarp-demo' if demo else 'zarp'))));self.path=base/'ui.json';self.demo=demo
        self.data={'autoConnect':False,'closeAction':'ask','routingEnabled':False,'preset':'lan','presets':copy.deepcopy(DEFAULT_PRESETS),'geoURLs':GEO_DEFAULT.copy(),'languageSystem':False}
        try:
            raw=json.loads(self.path.read_text());self.data.update({k:v for k,v in raw.items() if k in self.data})
        except (OSError,ValueError,TypeError):pass
    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd,name=tempfile.mkstemp(prefix='.ui-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'w') as f:json.dump(self.data,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
        finally:
            if os.path.exists(name):os.unlink(name)
    def autostart_path(self):
        if self.demo:return self.path.parent/'autostart-preview.desktop'
        return Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'autostart/zarp.desktop'
    def set_autostart(self,enabled):
        path=self.autostart_path()
        if enabled:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('[Desktop Entry]\nType=Application\nName=Zarp\nExec=zarp --autostart\nIcon=zarp\nTerminal=false\nX-GNOME-Autostart-enabled=true\n');path.chmod(0o600)
        else:path.unlink(missing_ok=True)

def parse_routes(preset):
    import ipaddress
    result=[]
    # Explicit rule priority from the Windows client.
    for action in ('block','proxy','direct'):
        groups={}
        for line in preset.get(action,'').splitlines():
            value=line.strip()
            if not value or value.startswith('#'):continue
            kind='domain_suffix'
            if ':' in value:
                prefix,rest=value.split(':',1)
                mapping={'full':'domain','domain':'domain_suffix','keyword':'domain_keyword','regexp':'domain_regex','geoip':'geoip','geosite':'geosite'}
                if prefix in mapping:kind,value=mapping[prefix],rest.strip()
            if kind=='domain_suffix':
                try:value=str(ipaddress.ip_network(value,strict=False));kind='ip_cidr'
                except ValueError:
                    if not re.fullmatch(r'[\w.-]+',value,re.ASCII):raise ValueError('Неверный домен: '+value)
            if kind in ('geoip','geosite') and not re.fullmatch(r'[a-z0-9_.!@-]{1,100}',value):raise ValueError('Неверная категория: '+value)
            if kind=='domain_regex':re.compile(value)
            if not value:raise ValueError('Пустое правило')
            groups.setdefault(kind,[]).append(value)
        result.extend({'action':action,'kind':kind,'values':values} for kind,values in groups.items())
    return result

def installed_apps():
    import shutil
    entries={}
    running={}
    for proc in Path('/proc').iterdir():
        try:
            if not proc.name.isdigit() or proc.stat().st_uid!=os.getuid():continue
            executable=os.readlink(proc/'exe')
            if executable.startswith('/') and os.path.isfile(executable):running[Path(executable).name]=executable
        except (OSError,PermissionError):continue
    roots=[Path('/usr/share/applications'),Path('/usr/local/share/applications'),Path.home()/'.local/share/applications']
    for root in roots:
        for path in root.glob('*.desktop'):
            try:
                section=False;fields={}
                for line in path.read_text(errors='replace').splitlines():
                    if line.startswith('['):section=line=='[Desktop Entry]'
                    elif section and '=' in line:
                        key,value=line.split('=',1);fields[key]=value
                if fields.get('NoDisplay')=='true' or fields.get('Hidden')=='true':continue
                args=shlex.split(fields.get('Exec',''))
                if not args:continue
                executable=shutil.which(args[0]) if not args[0].startswith('/') else args[0]
                if not executable or not os.path.isfile(executable):continue
                name=fields.get('Name',Path(executable).name);actual=running.get(Path(executable).name,executable)
                if Path(executable).name in ('snap','flatpak','env','gtk-launch'):continue
                entries[actual]=(name,actual)
            except (OSError,ValueError):continue
    for name,executable in running.items():entries.setdefault(executable,(name,executable))
    return sorted(entries.values(),key=lambda row:row[0].casefold())
