#!/usr/bin/env python3
"""Capture original-style Linux dialogs and animation frames, strictly offline."""
from pathlib import Path
import json,os,subprocess,sys,tempfile,time
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest
from desktop.zarp import Window,init_theme
from desktop import dialogs

def main():
    output=ROOT/'build/preview-linux';output.mkdir(parents=True,exist_ok=True)
    frames=ROOT/'build/animation-frames';frames.mkdir(exist_ok=True)
    app=QApplication([]);app.setQuitOnLastWindowClosed(False);init_theme(app)
    with tempfile.TemporaryDirectory(prefix='zarp-ui-capture-') as work:
        os.environ['ZARP_UI_STATE_HOME']=work+'/ui';socket=work+'/control.sock'
        daemon=subprocess.Popen([str(ROOT/'build/zarpd'),'--demo','--socket',socket,'--state',work+'/state'],stdout=subprocess.DEVNULL)
        window=None
        try:
            for _ in range(500):
                if Path(socket).exists():break
                time.sleep(.01)
            window=Window(socket,True);window.show()
            for _ in range(300):
                app.processEvents();time.sleep(.01)
                if window.config is not None and window.snapshot:break
            if window.config is None:raise RuntimeError('Demo service did not initialize')
            def shot(widget,name):app.processEvents();QTest.qWait(30);widget.grab().save(str(output/(name+'.png')))
            shot(window,'01-main-idle');window.toggle_log();QTest.qWait(210);shot(window,'02-main-log');window.toggle_log();QTest.qWait(210)
            window.language_menu();shot(window.popup,'03-language-popup');window.popup.close()
            connecting=False;connected=False
            for frame in range(112):
                if frame==18:window.start('connect')
                if frame==95 and connected:window.toggle()
                window.poll();QTest.qWait(33)
                state=window.snapshot.get('state')
                if state=='connecting' and not connecting:shot(window,'04-main-connecting');connecting=True
                if state=='connected' and not connected:shot(window,'05-main-connected');connected=True
                window.grab().save(str(frames/(f'{frame:04}.png')))
            if not connecting or not connected:raise RuntimeError('Connection states were not recorded')
            window.load_config();QTest.qWait(200)
            settings=window.open_settings();shot(settings,'06-settings');settings.country_menu();shot(settings.menu,'07-country-popup');settings.menu.close()
            window.start('scan',full=True);QTest.qWait(180);window.poll();QTest.qWait(50);shot(settings,'08-settings-searching');window.toggle();QTest.qWait(180);window.poll();QTest.qWait(100);shot(settings,'09-settings-results')
            connection=dialogs.ConnectionDialog(window);connection.show();shot(connection,'10-connection-warp');connection.use_proxy.setChecked(True);shot(connection,'11-connection-server');connection.link.setPlainText('vless://eb799b6d-443f-4540-9f56-333221145321@example.com:443?security=tls&type=ws&path=%2Fvpn#Preview');shot(connection,'12-connection-valid-server');connection.link.setPlainText('invalid://example');shot(connection,'13-connection-validation');connection.close()
            account=dialogs.AccountDialog(window);account.show();QTest.qWait(100);shot(account,'14-warp-plus');account.key.setText('invalid');shot(account,'15-warp-plus-validation');account.close()
            routing=dialogs.RoutingDialog(window);routing.show();shot(routing,'16-routing');routing.close()
            preset=dialogs.PresetDialog(window,{'id':'custom-preview','name':'Мои правила','direct':'','proxy':'','block':''},True);preset.show();shot(preset,'17-routing-preset');preset.close()
            geo=dialogs.GeoDialog(window);geo.show();QTest.qWait(100);shot(geo,'18-geodata');geo.close()
            apps=dialogs.AppsDialog(window);apps.show();QTest.qWait(180);shot(apps,'19-applications');apps.close()
            settings.close_action.showPopup();QTest.qWait(100);shot(settings.close_action.view().window(),'20-close-options-popup');settings.close_action.hidePopup();settings.close()
            close=dialogs.CloseDialog(window);close.show();shot(close,'21-close-action');close.close()
            custom=dialogs.CustomDialog(window);custom.show();shot(custom,'22-custom-strategies');custom.close()
            print('Captured Linux dialogs and 112 real Qt animation frames. Demo only; no network used.')
        finally:
            if window:
                window.exiting=True;window.timer.stop();window.save_timer.stop();window.pool.waitForDone(2000);app.processEvents();window.close()
            daemon.terminate()
            try:daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()

if __name__=='__main__':main()
