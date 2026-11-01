from __future__ import annotations
import copy,json,os,re,uuid
from pathlib import Path
from PySide6.QtCore import Qt,QPoint,QUrl,QSignalBlocker,QTimer
from PySide6.QtGui import QColor,QFont,QDesktopServices
from PySide6.QtWidgets import QDialog,QWidget,QTableWidget,QTableWidgetItem,QHeaderView,QAbstractItemView,QMenu,QComboBox,QPlainTextEdit,QLineEdit,QFileDialog,QMessageBox,QCheckBox
from desktop.widgets import *
from desktop.model import DEFAULT_PRESETS,GEO_DEFAULT,parse_routes,installed_apps,profile_uri,ROOT

def table(parent,headers,x,y,w,h,widths):
    t=QTableWidget(0,len(headers),parent);t.setGeometry(x,y,w,h);t.setFont(font(9));t.setHorizontalHeaderLabels(headers);t.verticalHeader().hide();t.verticalHeader().setDefaultSectionSize(20);t.verticalHeader().setMinimumSectionSize(18);t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows);t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers);t.setShowGrid(False);t.setWordWrap(False);t.horizontalHeader().setHighlightSections(False);t.horizontalHeader().setSectionsClickable(False);t.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter);t.horizontalHeader().setFixedHeight(23)
    for i,width in enumerate(widths):
        if width<0:t.horizontalHeader().setSectionResizeMode(i,QHeaderView.ResizeMode.Stretch)
        else:t.setColumnWidth(i,width)
    t.setItemDelegateForColumn(3,StatusColorDelegate(t))
    return t

class Dialog(QDialog):
    def __init__(self,window,title,width,height):
        super().__init__(window);self.window=window;self.t=window.t;self.setWindowTitle(title);self.setWindowIcon(app_icon(OFF));self.setFont(font());self.setFixedSize(width,height);self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint,False);self.setWindowModality(Qt.WindowModality.WindowModal);self.children_dialogs=[]
    def heading(self,text,x=18,y=16,w=None):return label(self,text,x+4,y,w or self.width()-40,24,12,bold=True)
    def note(self,text,x,y,w,h=40):return label(self,text,x,y,w,h,9.5,DIM,wrap=True)
    def open(self,cls):
        d=cls(self.window);d.setParent(self,d.windowFlags());d.setWindowModality(Qt.WindowModality.WindowModal);self.children_dialogs.append(d);d.show();return d
    def error(self,text):
        if hasattr(self,'message'):self.message.setText(self.window.message(text));self.message.setStyleSheet('color:'+BAD)
        else:self.window.show_error(text)

class SettingsDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('settings.caption'),800,764);self.setMinimumSize(760,744);self.setMaximumSize(16777215,16777215);self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint,True);self.last_table=None;self.loading=True;self.rebuild();window.changed.connect(self.refresh)
    def rebuild(self):
        self.t=self.window.t
        for child in self.findChildren(QWidget,options=Qt.FindChildOption.FindDirectChildrenOnly):child.hide();child.setParent(None);child.deleteLater()
        self.heading(self.t('settings.strategy'),18,14);self.note(self.t('settings.explain'),20,42,760,20)
        self.country=MenuButton(self);self.country.setGeometry(560,8,220,34);self.country.setFont(font(9));self.country.setCursor(Qt.CursorShape.PointingHandCursor);self.country.clicked.connect(self.country_menu)
        self.country.setStyleSheet('text-align:left;padding-left:12px;')
        self.table=table(self,['',self.t('col.strategy'),self.t('col.protocol'),self.t('col.result'),self.t('col.connect'),self.t('col.ping')],20,68,760,250,[26,250,110,-1,80,72]);self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection);self.table.itemDoubleClicked.connect(lambda _:self.use_selected());self.table.itemSelectionChanged.connect(self.update_actions)
        x=20
        self.use=button(self,self.t('btn.use'),x,330,112,callback=self.use_selected);x+=120
        self.test=button(self,self.t('btn.testSelected'),x,330,162,callback=self.test_selected);x+=170
        self.quick=button(self,self.t('btn.quickScan'),x,330,120,callback=lambda:self.window.start('scan'));x+=128
        self.full=button(self,self.t('btn.fullScan'),x,330,116,callback=lambda:self.window.start('scan',full=True));x+=124
        self.custom=button(self,self.t('btn.custom'),x,330,138,callback=lambda:self.open(CustomDialog))
        self.cancel=button(self,self.t('btn.cancel'),310,330,120,callback=self.window.toggle);self.cancel.hide()
        self.message=label(self,'',20,374,760,20,9,DIM)
        self.connection=button(self,self.t('btn.connection'),20,402,158,callback=lambda:self.open(ConnectionDialog));self.routing=button(self,self.t('btn.routing'),186,402,136,callback=lambda:self.open(RoutingDialog));self.apps=button(self,self.t('btn.apps'),330,402,166,callback=lambda:self.open(AppsDialog))
        self.heading(self.t('settings.options'),18,452)
        self.auto_connect=Toggle(self.t('opt.autoConnect'),self);self.auto_connect.setGeometry(20,486,430,28);self.auto_connect.setChecked(self.window.preferences.data['autoConnect']);self.auto_connect.toggled.connect(lambda v:self.preference('autoConnect',v))
        self.autostart=Toggle(self.t('opt.autostart'),self);self.autostart.setGeometry(20,520,430,28);self.autostart.setChecked(self.window.preferences.autostart_path().exists());self.autostart.toggled.connect(self.set_autostart)
        label(self,self.t('opt.onClose'),22,557,98,28,9);self.close_action=DarkSelect(self);self.close_action.setGeometry(120,554,240,32);self.close_action.addItems([self.t(k) for k in ('opt.closeAsk','opt.closeTray','opt.closeExit')]);self.close_action.setCurrentIndex(['ask','tray','exit'].index(self.window.preferences.data['closeAction']));self.close_action.currentIndexChanged.connect(lambda i:self.preference('closeAction',['ask','tray','exit'][i]))
        self.disconnect=Toggle(self.t('opt.disconnectOnExit'),self);self.disconnect.setGeometry(20,592,430,28)
        self.restrict=Toggle(self.t('opt.restrict'),self);self.restrict.setGeometry(20,626,430,28);self.restrict.setChecked(True);self.restrict.setEnabled(False);self.restrict.setToolTip('Linux: перехват всегда ограничен внешними соединениями выбранного VPN.')
        self.isolate=Toggle(self.t('opt.isolate'),self);self.isolate.setGeometry(20,660,430,28)
        self.auto_update=Toggle(self.t('opt.autoUpdate'),self);self.auto_update.setGeometry(20,694,430,28)
        label(self,self.t('opt.timeout'),464,484,200,32,9.5);self.timeout=NumberBox(self,3,60);self.timeout.move(664,484)
        label(self,self.t('opt.stopAfter'),464,528,192,44,9.5,wrap=True);self.quick_count=NumberBox(self,1,20);self.quick_count.move(664,530)
        self.folder=button(self,self.t('btn.dataFolder'),462,586,139,callback=self.open_data);self.diagnostics=button(self,'Диагностика' if self.t.code=='ru' else 'Diagnostics',609,586,171,callback=self.inspect)
        self.updates=button(self,self.t('btn.checkUpdates'),462,628,318,callback=self.check_updates);self.version=label(self,'zapret2 a414649',466,670,312,22,9,DIM)
        self.licenses=button(self,self.t('btn.licenses'),552,714,110,callback=self.open_licenses);button(self,self.t('btn.close'),670,714,110,callback=self.close)
        settings=(self.window.config or {}).get('settings',{})
        for widget,key,default in [(self.disconnect,'disconnectOnExit',True),(self.isolate,'isolateTests',True),(self.auto_update,'autoUpdateZapret',False)]:
            widget.setChecked(settings.get(key,default));widget.toggled.connect(lambda value,k=key:self.window.update_settings({k:value}))
        self.timeout.setValue(settings.get('timeoutSeconds',12));self.quick_count.setValue(settings.get('quickCount',3));self.timeout.valueChanged.connect(lambda v:self.window.update_settings({'timeoutSeconds':v}));self.quick_count.valueChanged.connect(lambda v:self.window.update_settings({'quickCount':v}));self.last_table=None;self.loading=False;self.base_geometry={child:child.geometry() for child in self.findChildren(QWidget,options=Qt.FindChildOption.FindDirectChildrenOnly)};self.layout_for_size();self.refresh()
    def resizeEvent(self,event):super().resizeEvent(event);self.layout_for_size()
    def layout_for_size(self):
        if not hasattr(self,'base_geometry'):return
        dx,dy=self.width()-800,self.height()-764
        for child,original in self.base_geometry.items():
            rect=original.adjusted(0,0,0,0)
            if child is self.table:rect.setWidth(original.width()+dx);rect.setHeight(original.height()+dy)
            elif child is self.country:rect.translate(dx,0)
            else:
                if original.y()>=330:rect.translate(0,dy)
                if child is self.licenses or original.y()==714:rect.translate(dx,0)
            child.setGeometry(rect)
    def preference(self,key,value):self.window.preferences.data[key]=value;self.window.preferences.save()
    def set_autostart(self,value):
        try:self.window.preferences.set_autostart(value)
        except OSError as e:self.error(str(e))
    def country_menu(self):
        self.menu=QMenu(self);countries=(self.window.config or {}).get('settings',{}).get('countries') or []
        for name,code in [(self.t('country.all'),'all'),(self.t('country.ru'),'ru'),(self.t('country.ir'),'ir'),(self.t('country.cn'),'cn')]:
            a=self.menu.addAction(name);a.setCheckable(True);a.setChecked((not countries) if code=='all' else code in countries);a.triggered.connect(lambda checked=False,c=code:self.select_country(c))
        self.menu.popup(self.country.mapToGlobal(QPoint(0,34)))
    def select_country(self,code):
        current=set((self.window.config or {}).get('settings',{}).get('countries') or [])
        if code=='all':current=set()
        elif code in current:current.remove(code)
        else:current.add(code)
        self.window.update_settings({'countries':sorted(current)},self.refresh)
    def refresh(self):
        if not self.isVisible() and self.last_table is not None:return
        snap=self.window.snapshot;settings=(self.window.config or {}).get('settings',{});countries=settings.get('countries') or [];country=', '.join(self.t('country.'+c) for c in countries) if countries else self.t('country.all');self.country.setText(self.t('filter.button',country))
        signature=json.dumps([snap.get('candidates'),snap.get('results'),snap.get('active')],sort_keys=True)
        if signature!=self.last_table:
            selected=set(self.selected_ids());scroll=self.table.verticalScrollBar().value();self.last_table=signature;rows=snap.get('candidates',[]);results={r['id']:r for r in snap.get('results',[])};self.table.setRowCount(len(rows))
            for row,candidate in enumerate(rows):
                result=results.get(candidate['id']);ok=bool(result and result.get('ok'));confirmed=bool(ok and result.get('confirmed'));current=candidate['id']==(snap.get('active') or (self.window.config or {}).get('selected'))
                status=self.t('result.notTested') if result is None else self.t('result.works2' if result.get('independent') else 'result.worksRepeated') if confirmed else self.t('result.works1') if ok else self.window.message(result.get('error') or 'no_confirmed_connection')
                result_color=DIM if result is None else OK if confirmed else BUSY if ok else BAD
                values=['✔' if current else '',candidate['name'],{'h3':'MASQUE / HTTP3','h2':'MASQUE / HTTP2','udp':'UDP'}.get(candidate['transport'],candidate['transport']),status,str(result.get('connectMS','')) if ok else '',str(result.get('latencyMS','')) if ok else '']
                for col,value in enumerate(values):
                    if col==1 and settings.get('source')=='warp':value='WARP '+value
                    item=QTableWidgetItem(value);item.setData(Qt.ItemDataRole.UserRole,candidate['id']);item.setForeground(QColor(result_color if col==3 else TEXT));self.table.setItem(row,col,item)
                    if col==3:item.setToolTip(value)
                    if current and col==1:item.setFont(font(9,bold=True))
                    if col>=4:item.setTextAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                if candidate['id'] in selected:self.table.item(row,0).setSelected(True)
            self.table.verticalScrollBar().setValue(scroll)
        self.message.setText(self.window.message(snap.get('detail','ready')) if snap.get('detail')!='ready' else '')
        self.update_actions()
    def selected_ids(self):return [self.table.item(index.row(),0).data(Qt.ItemDataRole.UserRole) for index in self.table.selectionModel().selectedRows()] if self.table.selectionModel() else []
    def update_actions(self):
        busy=self.window.snapshot.get('state') in ('searching','preparing','connecting','disconnecting');connected=self.window.snapshot.get('state')=='connected';ids=self.selected_ids();selected=bool(ids);self.use.setEnabled(selected and not busy and (not connected or ids[0]!=self.window.snapshot.get('active')));self.test.setEnabled(selected and not busy);self.quick.setVisible(not busy);self.full.setVisible(not busy);self.quick.setEnabled(not busy);self.full.setEnabled(not busy);self.cancel.setVisible(busy);self.connection.setEnabled(not busy);self.custom.setEnabled(not busy and not connected)
    def use_selected(self):
        ids=self.selected_ids()
        if ids:self.window.start('connect',ids[0])
    def test_selected(self):
        ids=self.selected_ids()
        if ids:self.window.start('test',ids[0],ids=ids if len(ids)>1 else None)
    def open_data(self):
        self.window.preferences.save();QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.window.preferences.path.parent)))
    def open_licenses(self):QDesktopServices.openUrl(QUrl.fromLocalFile(str(ROOT/'runtime/licenses' if (ROOT/'runtime/licenses').exists() else ROOT/'resources/licenses')))
    def inspect(self):self.window.call('inspect',success=lambda info:self.message.setText(json.dumps(info,ensure_ascii=False)))
    def check_updates(self):
        self.updates.setEnabled(False);self.version.setText(self.t('settings.checking'))
        def done(info):self.updates.setEnabled(True);self.version.setText('zapret2 '+info.get('current','')+(' → '+info['available'] if info.get('available') else ' - актуальная версия'))
        def error(text):self.updates.setEnabled(True);self.version.setText(self.window.message(text))
        self.window.call('check_updates',success=done,failure=error)

class ConnectionDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('endpoint.title'),640,457);self.heading(self.t('endpoint.title'));self.use_proxy=Toggle(self.t('proxy.enable'),self);self.use_proxy.setGeometry(20,52,600,28);self.source_id='';self.loading=False
        self.warp_panel=QWidget(self);self.warp_panel.setGeometry(20,88,600,258);label(self.warp_panel,self.t('endpoint.warp'),2,0,590,22,10.5,bold=True);label(self.warp_panel,self.t('endpoint.hint'),2,24,596,42,9.5,DIM,wrap=True)
        self.endpoints=QPlainTextEdit(self.warp_panel);self.endpoints.setGeometry(0,64,600,128);self.endpoints.setFont(QFont('DejaVu Sans Mono',10));self.endpoint_status=label(self.warp_panel,'',2,197,596,30,9.5,BAD,wrap=True);self.reset=button(self.warp_panel,self.t('endpoint.reset'),0,222,205,callback=lambda:self.endpoints.clear());button(self.warp_panel,self.t('warpPlus.title'),450,222,150,callback=lambda:self.open(AccountDialog))
        self.server_panel=QWidget(self);self.server_panel.setGeometry(20,88,600,258);label(self.server_panel,self.t('proxy.hint'),2,0,596,82,9.5,DIM,wrap=True)
        self.link=QPlainTextEdit(self.server_panel);self.link.setGeometry(0,90,600,92);self.link.setFont(QFont('DejaVu Sans Mono',10));self.link.setAccessibleName(self.t('proxy.link'));self.link_status=label(self.server_panel,'',2,186,596,38,9.5,DIM,wrap=True);self.ipv6=Toggle(self.t('proxy.ipv6'),self.server_panel);self.ipv6.setGeometry(0,228,230,28);label(self.server_panel,self.t('proxy.dns'),240,228,110,28,9.5);self.dns=QLineEdit(self.server_panel);self.dns.setGeometry(430,227,170,32)
        self.note(self.t('endpoint.applies'),22,357,596,40);self.save_button=button(self,self.t('btn.save'),392,406,110,True,self.save);button(self,self.t('btn.close'),510,406,110,callback=self.close)
        cfg=window.config or {'settings':{},'sources':[]};settings=cfg['settings'];self.use_proxy.setChecked(settings.get('source','warp')!='warp');self.ipv6.setChecked(settings.get('ipv6',True));self.dns.setText(settings.get('dns','1.1.1.1'));self.endpoints.setPlainText('\n'.join(settings.get('endpoints') or []))
        source=next((s for s in cfg['sources'] if s['id']==settings.get('source')),None)
        if source:
            self.source_id=source['id'];self.link.setPlainText(source.get('url') or '\n'.join(profile_uri(p) for p in source.get('servers',[])));self.link.setPlaceholderText(('Сохранено серверов: ' if self.t.code=='ru' else 'Saved servers: ')+str(len(source.get('servers',[]))))
        self.initial=self.values();self.use_proxy.toggled.connect(self.validate);self.link.textChanged.connect(self.validate);self.endpoints.textChanged.connect(self.validate);self.dns.textChanged.connect(self.validate);self.ipv6.toggled.connect(self.validate);self.validate()
    def values(self):return (self.use_proxy.isChecked(),self.link.toPlainText().strip(),self.endpoints.toPlainText().strip(),self.ipv6.isChecked(),self.dns.text())
    def validate(self):
        import ipaddress,urllib.parse
        proxy=self.use_proxy.isChecked();self.server_panel.setVisible(proxy);self.warp_panel.setVisible(not proxy);valid=True
        try:
            for value in self.endpoints.toPlainText().splitlines():
                if value.strip():
                    host,port=value.strip().rsplit(':',1);ipaddress.ip_address(host.strip('[]'));assert 1<=int(port)<=65535
            self.endpoint_status.setText('')
        except (ValueError,AssertionError):valid=False;self.endpoint_status.setText(self.t('endpoint.invalid'))
        self.reset.setVisible(bool(self.endpoints.toPlainText().strip()));value=self.link.toPlainText().strip()
        if proxy:
            try:ipaddress.ip_address(self.dns.text().strip())
            except ValueError:valid=False;self.link_status.setText(self.t('proxy.dnsInvalid'))
            if value:
                parsed=urllib.parse.urlparse(value);good=parsed.scheme in ('https','vless','trojan','hy2','hysteria2') and bool(parsed.hostname)
                valid=valid and good;self.link_status.setText(self.t('proxy.subscription',parsed.hostname) if good and parsed.scheme=='https' else self.t('proxy.scheme') if not good else parsed.scheme.upper()+': '+str(parsed.hostname));self.link_status.setStyleSheet('color:'+(DIM if good else BAD))
            elif not self.source_id:valid=False;self.link_status.clear()
        self.save_button.setEnabled(valid and not self.loading and (self.values()!=self.initial or value.startswith('https://')))
    def save(self):
        self.loading=True;self.validate();settings={'endpoints':[v.strip() for v in self.endpoints.toPlainText().splitlines() if v.strip()],'ipv6':self.ipv6.isChecked(),'dns':self.dns.text().strip()}
        def failed(error):self.loading=False;self.validate();self.link_status.setText(self.window.message(error));self.link_status.setStyleSheet('color:'+BAD)
        def configure(source):
            settings['source']=source;settings['server']=''
            if source=='warp':settings.update({'routes':[],'perApp':False})
            def done():self.loading=False;self.initial=self.values();self.window.load_config();self.accept()
            self.window.update_settings(settings,done,failed)
        if not self.use_proxy.isChecked():configure('warp');return
        value=self.link.toPlainText().strip()
        if not value:configure(self.source_id);return
        if self.source_id and value==self.initial[1]:
            if value.startswith('https://'):self.window.call('refresh',{'id':self.source_id},lambda _:configure(self.source_id),failed)
            else:configure(self.source_id)
            return
        def imported(info):
            self.source_id=info['id']
            if value.startswith('https://'):
                self.link_status.setText(self.t('proxy.subscriptionLoading'));self.window.call('refresh',{'id':self.source_id},lambda _:configure(self.source_id),failed)
            else:configure(self.source_id)
        self.window.call('import',{'name':'Мой сервер' if self.t.code=='ru' else 'My server','value':value},imported,failed)

class AccountDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('warpPlus.title'),600,365);self.heading(self.t('warpPlus.title'));self.note(self.t('warpPlus.hint'),20,52,560,60);self.account=self.note(self.t('warpPlus.account',self.t('warpPlus.unknown')),20,122,560,22);self.note(self.t('warpPlus.key'),20,158,560,20);self.key=QLineEdit(self);self.key.setGeometry(20,184,560,32);self.key.setEchoMode(QLineEdit.EchoMode.Password);self.key.setMaxLength(128);self.note(self.t('warpPlus.privacy'),20,224,560,40);self.message=self.note('',20,270,560,32);self.apply=button(self,self.t('warpPlus.apply'),20,312,150,True,lambda:self.run(True));self.refresh_button=button(self,self.t('warpPlus.refresh'),178,312,150,callback=lambda:self.run(False));button(self,self.t('btn.close'),470,312,110,callback=self.close);self.key.textChanged.connect(self.validate);self.validate();QTimer.singleShot(0,lambda:self.run(False))
    def validate(self):
        valid=bool(re.fullmatch(r'[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}',self.key.text()));self.apply.setEnabled(valid)
        self.message.setText(self.t('warpPlus.invalid') if self.key.text() and not valid else '');self.message.setStyleSheet('color:'+BAD)
    def run(self,apply):
        self.apply.setEnabled(False);self.refresh_button.setEnabled(False);self.message.setText(self.t('warpPlus.applying' if apply else 'warpPlus.loading'))
        def done(account):
            self.refresh_button.setEnabled(True);self.key.clear() if apply else None;self.account.setText(self.t('warpPlus.account',self.t({'free':'warpPlus.free','limited':'warpPlus.plus','unlimited':'warpPlus.unlimited','unknown':'warpPlus.unknown'}.get(account,'warpPlus.unknown'))));self.validate();self.message.setText(self.t('warpPlus.applied') if apply else '')
        def failed(error):self.refresh_button.setEnabled(True);self.validate();self.message.setText(self.window.message(error));self.message.setStyleSheet('color:'+BAD)
        self.window.call('license' if apply else 'account',{'key':self.key.text()} if apply else {},done,failed)

class CustomDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('btn.custom').rstrip('.'),740,470);self.heading(self.t('btn.custom').rstrip('.'));self.note('Название | h2/h3/udp | аргументы zapret2 | ru,ir,cn',20,50,700,30);self.editor=QPlainTextEdit(self);self.editor.setGeometry(20,88,700,280);self.editor.setFont(QFont('DejaVu Sans Mono',10));self.editor.setPlainText('\n'.join(s['name']+' | '+s['transport']+' | '+' '.join(s['args'])+' | '+','.join(s.get('countries') or []) for s in (window.config or {}).get('custom') or []));self.message=self.note('',20,374,700,34);button(self,self.t('btn.save'),492,418,110,True,self.save);button(self,self.t('btn.close'),610,418,110,callback=self.close)
    def save(self):self.window.call('strategies',{'text':self.editor.toPlainText()},lambda _:(self.window.load_config(),self.accept()),self.error)

class CloseDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('close.caption'),440,228);self.action='tray';self.heading(self.t('close.question'),20,18,400);self.note(self.t('close.trayInfo')+'\n'+self.t('close.exitDisconnects' if (window.config or {}).get('settings',{}).get('disconnectOnExit',True) else 'close.exitKeeps'),20,52,400,44);self.remember=QCheckBox(self.t('close.remember'),self);self.remember.setGeometry(20,104,400,24);self.note(self.t('close.hint'),20,136,400,24);button(self,self.t('close.toTray'),20,176,184,True,lambda:self.select('tray'));button(self,self.t('close.exit'),212,176,208,callback=lambda:self.select('exit'))
    def select(self,action):self.action=action;self.accept()

class RoutingDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('routing.title'),700,567);self.heading(self.t('routing.title'));self.enable=Toggle(self.t('routing.enable'),self);self.enable.setGeometry(20,52,660,28);self.enable.setChecked(window.preferences.data['routingEnabled']);self.enable.setEnabled(bool(window.config and window.config['settings']['source']!='warp'));self.note(self.t('routing.onlyProxy'),22,84,656,38);label(self,self.t('routing.presets'),22,129,600,24,10.5,bold=True)
        self.table=table(self,['',self.t('routing.presets'),self.t('routing.direct'),self.t('routing.proxy'),self.t('routing.block')],20,158,660,190,[26,-1,95,95,95]);self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection);self.table.itemSelectionChanged.connect(self.selection_changed);self.table.itemDoubleClicked.connect(lambda _:self.use())
        self.use_button=button(self,self.t('btn.use'),20,358,112,callback=self.use);button(self,self.t('btn.edit'),140,358,110,callback=self.edit);button(self,self.t('routing.addPreset'),258,358,134,callback=self.add);self.remove_button=button(self,self.t('routing.resetPreset'),400,358,130,callback=self.remove)
        self.note(self.t('routing.priority'),22,402,656,40);button(self,self.t('btn.geo'),20,445,190,callback=lambda:self.open(GeoDialog));self.message=self.note(self.t('settings.reconnect'),22,486,656,30);button(self,self.t('btn.close'),570,516,110,callback=self.close);self.enable.toggled.connect(self.enable_routes);self.fill()
    def fill(self,selected=None):
        presets=self.window.preferences.data['presets'];self.table.setRowCount(len(presets));active=self.window.preferences.data['preset']
        for row,preset in enumerate(presets):
            name=preset['name'] or self.t('routing.lanPreset' if preset['id']=='lan' else 'country.'+preset['id']);values=['✔' if preset['id']==active else '',name]+[str(len([v for v in preset.get(action,'').splitlines() if v.strip() and not v.strip().startswith('#')])) for action in ('direct','proxy','block')]
            for col,value in enumerate(values):item=QTableWidgetItem(value);item.setData(Qt.ItemDataRole.UserRole,preset['id']);self.table.setItem(row,col,item)
            if preset['id']==(selected or active):self.table.selectRow(row)
    def current(self):
        row=self.table.currentRow();return self.window.preferences.data['presets'][row] if row>=0 and row<len(self.window.preferences.data['presets']) else None
    def selection_changed(self):
        p=self.current();self.use_button.setEnabled(p is not None and self.enable.isEnabled());self.remove_button.setText(self.t('routing.resetPreset' if p and p['id'] in ('lan','ru','ir','cn') else 'routing.deletePreset'))
    def apply(self):
        prefs=self.window.preferences.data;p=next((p for p in prefs['presets'] if p['id']==prefs['preset']),None)
        try:routes=parse_routes(p) if prefs['routingEnabled'] and p else []
        except ValueError as e:self.error(str(e));return
        self.window.preferences.save()
        if self.window.config and self.window.config['settings']['source']!='warp':self.window.update_settings({'routes':routes})
    def enable_routes(self,enabled):self.window.preferences.data['routingEnabled']=enabled;self.apply()
    def use(self):
        p=self.current()
        if p:self.window.preferences.data['preset']=p['id'];self.apply();self.fill(p['id'])
    def edit(self):
        p=self.current()
        if p:self.edit_preset(p,False)
    def add(self):self.edit_preset({'id':'custom-'+uuid.uuid4().hex,'name':self.t('routing.customPreset'),'direct':'','proxy':'','block':''},True)
    def edit_preset(self,p,is_new):
        dialog=PresetDialog(self.window,p,is_new);self.children_dialogs.append(dialog)
        def accepted():
            presets=self.window.preferences.data['presets'];index=next((i for i,v in enumerate(presets) if v['id']==p['id']),len(presets))
            if index==len(presets):presets.append(dialog.result)
            else:presets[index]=dialog.result
            self.apply();self.fill(p['id'])
        dialog.accepted.connect(accepted);dialog.show();return dialog
    def remove(self):
        p=self.current()
        if not p:return
        original=next((v for v in DEFAULT_PRESETS if v['id']==p['id']),None)
        if original:p.update(copy.deepcopy(original))
        else:
            if QMessageBox.question(self,self.t('routing.title'),self.t('routing.deleteConfirm',p['name']))!=QMessageBox.StandardButton.Yes:return
            self.window.preferences.data['presets'].remove(p)
            if self.window.preferences.data['preset']==p['id']:self.window.preferences.data['preset']='lan'
        self.apply();self.fill()

class PresetDialog(Dialog):
    def __init__(self,window,preset,is_new=False):
        super().__init__(window,window.t('routing.addPreset' if is_new else 'routing.editTitle'),764,508);self.preset=copy.deepcopy(preset);self.result=None
        if preset['id'] not in ('lan','ru','ir','cn'):
            self.note(self.t('routing.name'),20,16,320,20);self.name=QLineEdit(self);self.name.setGeometry(20,40,320,32);self.name.setText(preset['name']);y=86
        else:self.name=None;self.heading(self.t('routing.lanPreset' if preset['id']=='lan' else 'country.'+preset['id']));y=54
        self.editors={}
        for i,action in enumerate(('direct','proxy','block')):
            x=20+i*242;label(self,self.t('routing.'+action),x,y,230,22,10.5,bold=True);editor=QPlainTextEdit(self);editor.setGeometry(x,y+28,230,250);editor.setFont(QFont('DejaVu Sans Mono',10));editor.setPlainText(preset.get(action,''));self.editors[action]=editor
        bottom=y+290;self.note(self.t('routing.syntax'),20,bottom,724,44);self.note(self.t('routing.priority'),20,bottom+48,724,38);self.message=label(self,'',20,bottom+88,724,30,9.5,BAD,wrap=True);self.setFixedHeight(bottom+178);button(self,self.t('btn.save'),516,bottom+126,110,True,self.save);button(self,self.t('btn.cancel'),634,bottom+126,110,callback=self.reject)
        if self.name is None:button(self,self.t('routing.resetPreset'),20,bottom+126,180,callback=self.reset)
    def reset(self):
        p=next(p for p in DEFAULT_PRESETS if p['id']==self.preset['id'])
        for key,editor in self.editors.items():editor.setPlainText(p.get(key,''))
    def save(self):
        p=copy.deepcopy(self.preset);p.update({k:editor.toPlainText().strip() for k,editor in self.editors.items()});p['name']=self.name.text().strip() if self.name else ''
        try:parse_routes(p)
        except (ValueError,re.error) as e:self.message.setText(str(e));return
        self.result=p;self.accept()

class GeoDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('geo.title'),680,470);self.heading(self.t('geo.title'));self.sections={}
        for i,kind in enumerate(('geoip','geosite')):
            y=54+i*160;label(self,'GeoIP' if kind=='geoip' else 'GeoSite',20,y,640,22,10.5,bold=True);self.note(self.t('geo.source'),22,y+24,640,20);url=QLineEdit(self);url.setGeometry(20,y+48,640,32);url.setText(window.preferences.data['geoURLs'][kind]);status=self.note('',22,y+84,640,28);download=button(self,self.t('geo.download'),20,y+114,134,callback=lambda checked=False,k=kind:self.download(k));button(self,self.t('geo.resetSource'),162,y+114,180,callback=lambda checked=False,k=kind:self.reset(k));self.sections[kind]=(url,status,download);url.textChanged.connect(lambda text,k=kind:self.url_changed(k,text))
        self.note(self.t('geo.format'),22,378,636,40);button(self,self.t('btn.close'),550,420,110,callback=self.close);self.refresh()
    def reset(self,kind):self.sections[kind][0].setText(GEO_DEFAULT[kind])
    def url_changed(self,kind,text):self.window.preferences.data['geoURLs'][kind]=text;self.window.preferences.save()
    def refresh(self):
        def loaded(states):
            for kind,parts in self.sections.items():
                state=states.get(kind,{});parts[1].setText(self.t('geo.ready',state.get('categories',0),state.get('updated','')) if state.get('categories') else self.t('geo.bundled' if kind=='geoip' else 'geo.missing'))
        self.window.call('geodata',success=loaded,failure=self.error)
    def download(self,kind):
        url,status,download=self.sections[kind];download.setEnabled(False);status.setText(self.t('geo.downloading',0))
        def done(_):download.setEnabled(True);self.refresh()
        def failed(error):download.setEnabled(True);status.setText(self.window.message(error));status.setStyleSheet('color:'+BAD)
        self.window.call('download_geo',{'kind':kind,'url':url.text().strip()},done,failed)

class AppsDialog(Dialog):
    def __init__(self,window):
        super().__init__(window,window.t('apps.title'),760,728);self.loading=True;self.rows=[];self.selected=set((window.config or {}).get('settings',{}).get('applications') or []);self.heading(self.t('apps.title'));self.enable=Toggle(self.t('apps.enable'),self);self.enable.setGeometry(20,52,720,28);self.enable.setChecked((window.config or {}).get('settings',{}).get('perApp',False));self.enable.setEnabled(bool(window.config and window.config['settings']['source']!='warp'));self.note(self.t('apps.onlyProxy'),22,84,716,38);self.note(self.t('apps.hint'),22,124,716,52);self.note(self.t('settings.reconnect'),22,180,716,20);self.summary=self.note(self.t('apps.loading'),22,204,716,20);self.note(self.t('apps.search'),22,232,716,20);self.search=QLineEdit(self);self.search.setGeometry(20,254,720,32);self.table=table(self,['',self.t('apps.colName'),self.t('apps.colPath')],20,296,720,370,[26,240,-1]);self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection);self.table.itemChanged.connect(self.item_changed);self.search.textChanged.connect(self.fill);button(self,self.t('apps.add'),20,684,162,callback=self.add);self.refresh_button=button(self,self.t('apps.refresh'),190,684,110,callback=self.load);button(self,self.t('btn.close'),630,684,110,callback=self.close);self.enable.toggled.connect(self.save);self.load()
    def load(self):
        self.refresh_button.setEnabled(False)
        def loaded(rows):self.rows=rows;self.refresh_button.setEnabled(True);self.fill()
        self.window.job(installed_apps,loaded,self.error)
    def fill(self):
        self.loading=True;query=self.search.text().casefold();rows={path:(name,path) for name,path in self.rows}
        for path in self.selected:rows.setdefault(path,(Path(path).name,path))
        rows=[v for v in sorted(rows.values(),key=lambda x:x[0].casefold()) if not query or query in (v[0]+' '+v[1]).casefold()];self.table.setRowCount(len(rows))
        for i,(name,path) in enumerate(rows):
            check=QTableWidgetItem();check.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsUserCheckable|Qt.ItemFlag.ItemIsSelectable);check.setCheckState(Qt.CheckState.Checked if path in self.selected else Qt.CheckState.Unchecked);check.setData(Qt.ItemDataRole.UserRole,path);self.table.setItem(i,0,check);self.table.setItem(i,1,QTableWidgetItem(name));self.table.setItem(i,2,QTableWidgetItem(path))
        self.summary.setText(self.t('apps.selected',len(self.selected)));self.loading=False
    def item_changed(self,item):
        if self.loading or item.column()!=0:return
        path=item.data(Qt.ItemDataRole.UserRole)
        if item.checkState()==Qt.CheckState.Checked:self.selected.add(path)
        else:self.selected.discard(path)
        self.save();self.summary.setText(self.t('apps.selected',len(self.selected)))
    def save(self,*args):
        if self.enable.isChecked() and not self.selected:self.summary.setText(self.t('apps.empty'));return
        self.window.update_settings({'applications':sorted(self.selected),'perApp':self.enable.isChecked()})
    def add(self):
        path,_=QFileDialog.getOpenFileName(self,self.t('apps.pickTitle'),'/usr/bin','All files (*)')
        if path:self.selected.add(path);self.fill();self.save()
