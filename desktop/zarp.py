#!/usr/bin/env python3
"""The original compact Zarp interface, backed by the Linux system service."""
from __future__ import annotations
import argparse,copy,json,os,socket,subprocess,sys
from pathlib import Path
from PySide6.QtCore import Qt,QTimer,QThreadPool,Signal,QVariantAnimation,QEasingCurve,QPoint,QLocale,QUrl
from PySide6.QtGui import QAction,QDesktopServices
from PySide6.QtWidgets import QApplication,QMainWindow,QWidget,QPlainTextEdit,QProgressBar,QMenu,QSystemTrayIcon,QMessageBox
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from desktop.client import rpc,Job,Reply
from desktop.model import Preferences,Translation,LANGUAGES
from desktop.widgets import *

class Window(QMainWindow):
    changed=Signal()
    def __init__(self,path,demo=False):
        super().__init__();self.path,self.demo=path,demo;self.config=None;self.snapshot={};self.inspection={};self.preferences=Preferences(demo);self.t=Translation();self.exiting=False;self.polling=False;self.config_loading=False;self.jobs=set();self.pool=QThreadPool(self);self.pool.setMaxThreadCount(6);self.settings_window=None;self.log_expanded=False;self.last_events=[];self.did_autoconnect=False;self.settings_pending={};self.saving=False
        self.setWindowTitle('Zarp - демо' if demo else 'Zarp');self.setWindowIcon(app_icon());self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint,False);self.setFixedSize(380,500);self.body=QWidget(self);self.setCentralWidget(self.body)
        self.title=label(self.body,'Zarp',28,16,180,30,18,bold=True);self.subtitle=label(self.body,'',28,52,330,20,9,DIM)
        self.language=IconButton('language',self.body);self.language.move(272,20);self.language.clicked.connect(self.language_menu)
        self.settings=IconButton('settings',self.body);self.settings.move(318,20);self.settings.clicked.connect(self.open_settings)
        self.power=PowerButton(self.body);self.power.move(90,92);self.power.clicked.connect(self.toggle)
        self.status=label(self.body,'',10,306,360,34,16,bold=True);self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail=label(self.body,'',20,342,340,40,9.5,DIM,wrap=True);self.detail.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop)
        self.progress=QProgressBar(self.body);self.progress.setGeometry(50,390,280,4);self.progress.setTextVisible(False);self.progress.hide()
        self.hint=label(self.body,'',20,404,340,52,8.5,DIM,wrap=True);self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.log_toggle=button(self.body,'',22,462,110,callback=self.toggle_log);self.log_toggle.setStyleSheet('QPushButton{background:transparent;border:0;color:'+DIM+';padding:0;text-align:left;}QPushButton:hover{color:'+TEXT+';}')
        self.log=QPlainTextEdit(self.body);self.log.setReadOnly(True);self.log.setGeometry(14,494,352,176);self.log.setFont(QFont('DejaVu Sans Mono',11));self.log.setStyleSheet('background:'+PANEL+';color:'+DIM+';border:0;border-radius:0;padding:6px;');self.log.hide()
        self.demo_badge=label(self.body,'ДЕМО · без сети',242,466,118,20,8,DIM);self.demo_badge.setAlignment(Qt.AlignmentFlag.AlignRight);self.demo_badge.setVisible(demo);self.demo_badge.setToolTip('Все результаты смоделированы. Сеть и аккаунт WARP не используются.')
        self.height_animation=QVariantAnimation(self);self.height_animation.setDuration(170);self.height_animation.setEasingCurve(QEasingCurve.Type.OutCubic);self.height_animation.valueChanged.connect(lambda value:self.setFixedHeight(int(value)))
        self.save_timer=QTimer(self);self.save_timer.setSingleShot(True);self.save_timer.setInterval(140);self.save_timer.timeout.connect(self.flush_settings)
        self.tray=QSystemTrayIcon(app_icon(OFF),self);self.tray_menu=QMenu();self.tray.setContextMenu(self.tray_menu);self.tray.activated.connect(lambda reason:self.restore() if reason==QSystemTrayIcon.ActivationReason.Trigger else None)
        if QSystemTrayIcon.isSystemTrayAvailable():self.tray.show()
        self.timer=QTimer(self);self.timer.setInterval(250);self.timer.timeout.connect(self.poll);self.timer.start();self.retranslate();self.load_config();self.poll()
    def job(self,function,success=None,failure=None):
        if not hasattr(self,'retired_jobs'):
            self.retired_jobs=[];self.reap_timer=QTimer(self);self.reap_timer.setInterval(25);self.reap_timer.timeout.connect(self.reap_jobs)
            self.pool.setExpiryTimeout(-1)
        task=Job(function,self);reply=Reply(self,task,success,failure or self.show_error);self.jobs.add(task);task.signals.result.connect(reply.done,Qt.ConnectionType.QueuedConnection);task.signals.error.connect(reply.fail,Qt.ConnectionType.QueuedConnection);self.pool.start(task)
    def finish_job(self,task):
        self.jobs.discard(task);self.retired_jobs.append(task);self.reap_timer.start()
    def reap_jobs(self):
        # A queued result can arrive before QRunnable.run() has returned.
        # Keep C++ ownership in Python and release workers on the GUI thread,
        # only once the pool has stopped using them.
        if self.pool.activeThreadCount():return
        retired,self.retired_jobs=self.retired_jobs,[]
        for task in retired:task.function=None;task.signals.deleteLater()
        self.reap_timer.stop()
    def quit_when_idle(self):
        if self.jobs or self.pool.activeThreadCount():QTimer.singleShot(25,self.quit_when_idle);return
        self.reap_jobs();self.pool.waitForDone();QApplication.instance().quit()
    def call(self,command,params=None,success=None,failure=None):self.job(lambda:rpc(self.path,command,params,self.demo),success,failure)
    def load_config(self):
        if self.config_loading:return
        self.config_loading=True
        def loaded(config):
            self.config_loading=False;self.config=config;self.t=Translation(config['settings']['language']);self.retranslate();self.changed.emit()
            if not self.did_autoconnect:
                self.did_autoconnect=True
                if self.preferences.data['autoConnect'] and config.get('selected'):QTimer.singleShot(200,self.toggle)
        def failed(error):self.config_loading=False;self.detail.setText(self.message(error))
        self.call('get_config',success=loaded,failure=failed)
    def poll(self):
        if self.polling or self.exiting:return
        self.polling=True
        def loaded(snapshot):
            self.polling=False;self.snapshot=snapshot;self.render()
            if self.config is None:self.load_config()
            self.changed.emit()
        def failed(error):self.polling=False;self.power.set_state('off');self.detail.setText(self.message(error));self.status.setText('Служба недоступна' if self.t.code=='ru' else 'Service unavailable')
        self.call('status',success=loaded,failure=failed)
    def retranslate(self):
        self.language.setAccessibleName(self.t('main.languageTip'));self.settings.setAccessibleName(self.t('main.settingsTip'))
        self.language.setToolTip(self.t('main.languageTip'));self.settings.setToolTip(self.t('main.settingsTip'));self.log_toggle.setText(self.t('main.logHide' if self.log_expanded else 'main.logShow'));self.tray_menu.clear()
        for text,fn in [('tray.open',self.restore),('tray.connect',self.toggle),('tray.settings',self.open_settings),('tray.exit',self.exit_app)]:self.tray_menu.addAction(self.t(text),fn)
        self.render()
    def render(self):
        state=self.snapshot.get('state','idle');busy=state in ('preparing','searching','connecting','disconnecting');on=state=='connected';self.power.set_state('on' if on else 'busy' if busy else 'off');self.power.setEnabled(self.config is not None);self.power.setAccessibleName(self.t('tray.cancel' if busy else 'tray.disconnect' if on else 'tray.connect'))
        key={'idle':'disconnected','error':'unknown','cleanup_failed':'unknown'}.get(state,state);self.status.setText(self.t('status.'+key));self.status.setStyleSheet('background:transparent;color:'+(ACCENT if on else BUSY if busy else BAD if state in ('error','cleanup_failed') else TEXT)+';')
        custom=self.config is not None and self.config['settings']['source']!='warp';self.subtitle.setText(self.t('proxy.subtitle' if custom else 'main.subtitle'));detail=self.snapshot.get('detail','ready');measurement=self.snapshot.get('measurement')
        if on and measurement:
            active=next((c['name'] for c in self.snapshot.get('candidates',[]) if c['id']==self.snapshot.get('active')),'');self.detail.setText(self.t('detail.strategy',('WARP ' if not custom else '')+active));self.detail.setToolTip(('Подключение: {0} мс · пинг: {1} мс\n{2}' if self.t.code=='ru' else 'Connected: {0} ms · latency: {1} ms\n{2}').format(measurement.get('connectMS',0),measurement.get('latencyMS',0),measurement.get('endpoint','')))
        else:self.detail.setText('' if detail in ('ready','connected','search_finished') else self.message(detail))
        self.hint.setText(self.t('hint.disconnect' if on else 'hint.cancel' if busy else 'hint.connect' if self.config and self.config.get('selected') else 'hint.proxyFirstRun' if custom else 'hint.firstRun'))
        total=self.snapshot.get('total',0);self.progress.setVisible(total>0 and busy);self.progress.setRange(0,max(1,total));self.progress.setValue(self.snapshot.get('done',0));self.tray.setIcon(app_icon(ACCENT if on else BUSY if busy else OFF));self.tray.setToolTip('Zarp: '+self.status.text())
        events=[event.get('when','')+' '+self.message(event.get('message','')) for event in self.snapshot.get('events',[])]
        if events!=self.last_events:self.last_events=events;self.log.setPlainText('\n'.join(events));self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())
    def message(self,code):
        if self.t.code=='ru' and code.startswith('strategy_mtu_incompatible:'):
            parts=code.split(':')
            if len(parts)==3 and all(value.isdigit() for value in parts[1:]):return 'MTU '+parts[1]+': требуется не менее '+parts[2]
        if code in ('disconnected','connected','searching','tests_finished'):return self.t({'disconnected':'detail.disconnected','connected':'status.connected','searching':'status.searching','tests_finished':'detail.disconnected'}[code])
        messages={'service':'Служба Zarp недоступна. Запустите установленную системную службу.','checking_system':'Проверяю систему…','checking_connection':'Проверяю соединение…','connection_lost':'Соединение потеряно','foreign_vpn_detected':'Обнаружен другой активный VPN. Отключите его перед поиском.','kernel_nft_socket_required_for_warp':'В ядре Linux нет nft_socket, необходимого для перехвата WARP.','cancelled':'Операция отменена','cleanup_failed':'Не удалось завершить отключение. Повторите попытку.','demo_no_network_changes':'Демо: сеть не используется','demo_does_not_download':'В деморежиме загрузки отключены.','demo_does_not_register_accounts':'Демо не меняет аккаунт WARP.','no_compatible_strategies':'Нет совместимых стратегий.','strategy_not_applied':'Применение стратегии не подтверждено.','warp_terms_required':'Необходимо принять условия Cloudflare WARP.','no_confirmed_connection':'Рабочее соединение не найдено.','settings_saved':'Настройки сохранены.'}
        messages.update({'kernel_warp_cgroup_filter_unavailable':'Не удалось включить перехват WARP: нужны nft_socket либо xt_cgroup и iptables-nft.','warp_cgroup_compat_tools_missing':'Установите iptables с поддержкой nftables для перехвата WARP.','warp_cgroup_compat_failed':'Не удалось включить cgroup-фильтр WARP.','automatic_warp_install_requires_ubuntu_or_debian':'На этой системе пока нужно отдельно установить официальный клиент WARP.'})
        messages.update({'warp_connect_timeout':'нет подключения за '+str((self.config or {}).get('settings',{}).get('timeoutSeconds',12))+' с','tunnel_https_failed':'не прошла проверка HTTPS через туннель','nfqws_stopped':'остановился обработчик zapret2','traffic_is_not_warp':'трафик не прошёл через WARP','tunnel_probe_invalid':'некорректный ответ при проверке туннеля'})
        messages.update({'warp_service_not_ready':'Служба WARP не успела запуститься. Проверьте её состояние.','warp_registration_status_unavailable':'Не удалось прочитать состояние регистрации WARP. Аккаунт сохранён.','warp_registration_pending_check_service':'Ответ на регистрацию не получен. Нужно проверить службу WARP; повторный аккаунт не создаётся.','nfqws_packet_exceeds_mtu':'Пакет стратегии превышает MTU интерфейса.','nfqws_send_blocked':'Отправка пакета запрещена firewall или ядром Linux.','nfqws_send_failed':'Не удалось отправить пакет стратегии zapret2.','nfqws_lua_error':'Ошибка выполнения Lua-стратегии zapret2.'})
        messages.update({'warp_fragment_firewall_not_ready':'WARP не подготовил firewall для выбранного сервера.','warp_fragment_firewall_install_failed':'Не удалось разрешить обработанные IP-фрагменты WARP.','warp_fragment_firewall_cleanup_failed':'Не удалось удалить правило IP-фрагментов Zarp.','warp_fragment_pause_failed':'Не удалось приостановить zapret2 для настройки фрагментации.','warp_fragment_resume_failed':'Не удалось возобновить zapret2 после настройки фрагментации.'})
        if self.t.code=='ru' and code in messages:return messages[code]
        if ':' in code:
            phase,*args=code.split(':');title={'testing':'Проверка стратегии','applying':'Подключение','registration_strategy':'Регистрация WARP через zapret2','download_strategy':'Загрузка через zapret2'}.get(phase,phase.replace('_',' '));return title+': '+': '.join(args)
        return code.replace('_',' ')
    def show_error(self,error):
        self.detail.setText(self.message(error));self.detail.setToolTip(self.message(error))
        if self.settings_window and self.settings_window.isVisible():self.settings_window.message.setText(self.message(error))
    def update_settings(self,changes,done=None,failure=None):
        if self.config is None:return
        self.settings_pending.update(changes)
        if done:self.flush_settings(done,failure)
        else:self.save_timer.start()
    def flush_settings(self,done=None,failure=None):
        if self.saving:QTimer.singleShot(80,lambda:self.flush_settings(done,failure));return
        if not self.settings_pending:
            if done:done()
            return
        changes=self.settings_pending;self.settings_pending={};settings=copy.deepcopy(self.config['settings']);settings.update(changes);self.saving=True
        def saved(_):
            self.saving=False;self.config['settings']=settings;self.t=Translation(settings['language']);self.retranslate();self.changed.emit()
            if self.settings_pending:self.flush_settings(done,failure)
            elif done:done()
        def failed(error):
            self.saving=False;self.show_error(error);self.changed.emit()
            if failure:failure(error)
        self.call('configure',settings,saved,failed)
    def ensure_terms(self,action):
        if self.demo or not self.config or self.config['settings']['source']!='warp' or self.config['settings']['acceptedTerms']:action();return
        prompt=QMessageBox(self);prompt.setWindowTitle('Cloudflare WARP');prompt.setText('Zarp скачает официальный клиент WARP и зарегистрирует устройство через zapret2. Принять условия Cloudflare WARP?\n\nhttps://www.cloudflare.com/application/terms/');prompt.setStandardButtons(QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
        if prompt.exec()==QMessageBox.StandardButton.Yes:self.update_settings({'acceptedTerms':True},action)
    def toggle(self):
        if self.snapshot.get('state') in ('connected','preparing','searching','connecting','disconnecting','cleanup_failed'):self.call('disconnect',success=lambda _:self.poll())
        else:self.start('connect')
    def start(self,kind,id='',full=False,ids=None):
        if not self.config:return
        def run():
            params={'id':id,'full':full}
            if ids:params['ids']=ids
            def begin():self.call(kind,params,success=lambda _:self.poll())
            if self.snapshot.get('state')=='connected':self.call('disconnect',success=lambda _:begin())
            else:begin()
        self.ensure_terms(lambda:self.flush_settings(run))
    def toggle_log(self):
        self.log_expanded=not self.log_expanded;self.log.setVisible(self.log_expanded);self.log_toggle.setText(self.t('main.logHide' if self.log_expanded else 'main.logShow'));self.height_animation.stop();self.height_animation.setStartValue(self.height());self.height_animation.setEndValue(690 if self.log_expanded else 500);self.height_animation.start()
    def language_menu(self):
        self.popup=QMenu(self);system=QLocale.system().name().split('_')[0];system=system if system in dict(LANGUAGES) else 'en';self.popup.addAction(self.t('lang.system',dict(LANGUAGES)[system]),lambda:self.set_language(system,True));self.popup.addSeparator()
        for code,name in LANGUAGES:
            action=self.popup.addAction(name);action.setCheckable(True);action.setChecked(self.t.code==code and not self.preferences.data['languageSystem']);action.triggered.connect(lambda checked=False,c=code:self.set_language(c))
        self.popup.popup(self.language.mapToGlobal(QPoint(self.language.width()-185,self.language.height()+4)))
    def set_language(self,code,system=False):
        self.preferences.data['languageSystem']=system;self.preferences.save();self.update_settings({'language':code},lambda:self.settings_window.rebuild() if self.settings_window and self.settings_window.isVisible() else None)
    def open_settings(self):
        from desktop.dialogs import SettingsDialog
        if self.settings_window and self.settings_window.isVisible():self.settings_window.raise_();self.settings_window.activateWindow();return self.settings_window
        self.settings_window=SettingsDialog(self);self.settings_window.show();return self.settings_window
    def restore(self):self.showNormal();self.raise_();self.activateWindow()
    def closeEvent(self,event):
        if self.exiting:event.accept();return
        action=self.preferences.data['closeAction']
        if action=='ask':
            from desktop.dialogs import CloseDialog
            prompt=CloseDialog(self)
            if not prompt.exec():event.ignore();return
            action=prompt.action
            if prompt.remember.isChecked():self.preferences.data['closeAction']=action;self.preferences.save()
        if action=='tray' and QSystemTrayIcon.isSystemTrayAvailable():self.hide();event.ignore()
        else:event.ignore();self.exit_app()
    def exit_app(self):
        if self.exiting:return
        self.exiting=True;self.timer.stop();self.save_timer.stop()
        def finish():
            self.tray.hide()
            if self.config and self.config['settings']['disconnectOnExit']:self.call('disconnect',success=lambda _:self.quit_when_idle(),failure=lambda _:self.quit_when_idle())
            else:self.quit_when_idle()
        def failed(error):self.exiting=False;self.timer.start();self.restore();self.show_error(error)
        self.flush_settings(finish,failed)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--demo',action='store_true');parser.add_argument('--autostart',action='store_true');parser.add_argument('--socket');parser.add_argument('--screenshot',type=Path);args=parser.parse_args()
    if args.screenshot and not args.demo:parser.error('--screenshot requires --demo')
    if os.geteuid()==0:raise SystemExit('Run the desktop as your regular user.')
    demo_path=str(Path(os.environ.get('XDG_RUNTIME_DIR','/tmp'))/('zarp-demo.sock' if os.environ.get('XDG_RUNTIME_DIR') else f'zarp-demo-{os.getuid()}.sock'));path=args.socket or (demo_path if args.demo else '/run/zarp/control.sock');daemon=None
    if args.demo:
        try:rpc(path,'status',demo=True)
        except OSError:
            binary=next((p for p in (ROOT/'build/zarpd',ROOT/'zarpd') if p.is_file()),None)
            if not binary:raise SystemExit('Build the daemon first: make build')
            daemon=subprocess.Popen([str(binary),'--demo','--socket',path],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    elif not Path(path).exists() and Path('/usr/lib/zarp/start-service').exists():subprocess.Popen(['pkexec','/usr/lib/zarp/start-service'],stdin=subprocess.DEVNULL)
    app=QApplication(sys.argv[:1]);app.setApplicationName('Zarp');app.setDesktopFileName('zarp');init_theme(app);window=Window(path,args.demo)
    if not args.autostart or not QSystemTrayIcon.isSystemTrayAvailable():window.show()
    if args.screenshot:
        def capture():window.grab().save(str(args.screenshot));window.exiting=True;app.quit()
        QTimer.singleShot(1800,capture)
    code=app.exec()
    if daemon and (args.screenshot or not window.config or window.config['settings']['disconnectOnExit']):
        daemon.terminate()
        try:daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
    sys.exit(code)

if __name__=='__main__':main()
