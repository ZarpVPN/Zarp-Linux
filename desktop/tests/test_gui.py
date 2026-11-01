import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import gc
import threading
import weakref

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = Path(__file__).resolve().parents[2]
DESKTOP_ROOT = Path(os.environ.get('ZARP_DESKTOP_ROOT', ROOT))
DAEMON = Path(os.environ.get('ZARP_TEST_DAEMON', ROOT / 'build/zarpd'))
spec = importlib.util.spec_from_file_location('zarp_desktop', DESKTOP_ROOT / 'desktop/zarp.py')
desktop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(desktop)
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt


class DesktopIntegrationTests(unittest.TestCase):
    def test_result_can_arrive_before_worker_has_returned(self):
        from desktop.client import Job,Reply
        release=threading.Event();received=[]
        class PausedWorker(Job):
            def run(self):
                self.signals.result.emit('result')
                release.wait(5)
        task=PausedWorker(lambda:None,self.window);reference=weakref.ref(task)
        reply=Reply(self.window,task,received.append,received.append)
        task.signals.result.connect(reply.done,Qt.ConnectionType.QueuedConnection)
        self.window.jobs.add(task);self.window.pool.start(task);del task
        try:
            self.wait(lambda:received==['result'])
            gc.collect();self.window.reap_jobs()
            self.assertIsNotNone(reference())
            self.assertGreater(self.window.pool.activeThreadCount(),0)
        finally:release.set()
        self.wait(lambda:self.window.pool.activeThreadCount()==0)
        self.window.reap_jobs();self.app.processEvents();gc.collect()
        self.assertEqual(self.window.retired_jobs,[])
    @classmethod
    def setUpClass(cls):
        if not DAEMON.exists():
            raise unittest.SkipTest('Build the daemon with make build')
        cls.app = QApplication.instance() or QApplication([])
        desktop.init_theme(cls.app)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='zarp-gui-')
        self.previous_ui=os.environ.get('ZARP_UI_STATE_HOME');os.environ['ZARP_UI_STATE_HOME']=str(Path(self.work.name)/'ui')
        self.socket = str(Path(self.work.name) / 'control.sock')
        self.process = subprocess.Popen([str(DAEMON), '--demo', '--socket', self.socket,
                                         '--state', str(Path(self.work.name) / 'state')], stdout=subprocess.DEVNULL)
        for _ in range(200):
            if Path(self.socket).exists():
                break
            time.sleep(0.01)
        self.window = desktop.Window(self.socket, True)
        self.window.show()
        self.wait(lambda: self.window.config is not None and bool(self.window.snapshot))

    def wait(self, condition, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return
            time.sleep(0.01)
        stored = desktop.rpc(self.socket, 'get_config', demo=True)
        self.fail('GUI operation did not finish; stored settings: ' + str(stored['settings']) + '; displayed: ' + str(self.window.config['settings']))

    def tearDown(self):
        self.window.timer.stop()
        self.window.save_timer.stop()
        self.window.exiting = True
        self.window.close()
        self.process.terminate()
        self.process.wait(timeout=5)
        self.window.pool.waitForDone(1000)
        self.app.processEvents()
        self.window.deleteLater()
        self.work.cleanup()
        if self.previous_ui is None:os.environ.pop('ZARP_UI_STATE_HOME',None)
        else:os.environ['ZARP_UI_STATE_HOME']=self.previous_ui

    def test_discovery_and_disconnect_use_the_real_control_socket(self):
        self.assertTrue(self.window.snapshot['demo'])
        settings=self.window.open_settings()
        self.assertGreater(settings.table.rowCount(), 0)
        self.window.start('scan')
        self.wait(lambda: self.window.snapshot.get('state') == 'connected')
        self.assertTrue(self.window.snapshot['measurement']['applied'])
        self.assertGreaterEqual(sum(r.get('confirmed', False) for r in self.window.snapshot['results']), 3)
        previous=self.window.snapshot['active'];candidate=next(c for c in self.window.snapshot['candidates'] if c['id']!=previous)
        self.window.start('connect',candidate['id']);self.wait(lambda:self.window.snapshot.get('state')=='connected' and self.window.snapshot.get('active')==candidate['id'])
        self.window.toggle()
        self.wait(lambda: self.window.snapshot.get('state') == 'idle')

    def test_settings_round_trip_and_mode_guard(self):
        with self.assertRaisesRegex(RuntimeError, 'control_mode_mismatch'):
            desktop.rpc(self.socket, 'connect', demo=False)
        settings=self.window.open_settings()
        settings.timeout.setValue(19)
        settings.select_country('ru')
        self.wait(lambda: self.window.config['settings']['timeoutSeconds'] == 19)
        self.assertEqual(self.window.config['settings']['countries'], ['ru'])

    def test_native_dialogs_render_and_busy_indicator_moves(self):
        from desktop import dialogs
        output=ROOT/'build/preview-linux';output.mkdir(parents=True,exist_ok=True)
        self.window.grab().save(str(output/'01-main-idle.png'))
        QTest.mouseClick(self.window.log_toggle,Qt.MouseButton.LeftButton)
        self.wait(lambda:self.window.height()==690)
        self.window.grab().save(str(output/'02-main-log.png'))
        QTest.mouseClick(self.window.log_toggle,Qt.MouseButton.LeftButton)
        self.wait(lambda:self.window.height()==500)
        self.window.language_menu();self.app.processEvents();self.window.popup.grab().save(str(output/'03-language-popup.png'));self.window.popup.close()
        self.window.power.set_state('busy');angle=self.window.power.angle;QTest.qWait(70);self.assertNotEqual(angle,self.window.power.angle);self.window.grab().save(str(output/'04-main-connecting.png'));self.window.power.set_state('off')
        for i,cls in enumerate((dialogs.SettingsDialog,dialogs.ConnectionDialog,dialogs.AccountDialog,dialogs.CustomDialog,dialogs.RoutingDialog,dialogs.GeoDialog,dialogs.AppsDialog,dialogs.CloseDialog),start=5):
            dialog=cls(self.window);dialog.show();QTest.qWait(100);dialog.grab().save(str(output/(f'{i:02}-'+cls.__name__+'.png')))
            self.assertGreater(dialog.width(),300);self.assertGreater(dialog.height(),100);dialog.close()
        preset=dialogs.PresetDialog(self.window,{'id':'custom-test','name':'Test','direct':'geoip:private','proxy':'domain:example.com','block':'keyword:ads'},True);preset.show();QTest.qWait(50);preset.grab().save(str(output/'13-preset.png'));preset.save();self.assertIsNotNone(preset.result)

    def test_server_import_and_routing_preferences_reach_the_daemon(self):
        from desktop.dialogs import ConnectionDialog,RoutingDialog
        connection=ConnectionDialog(self.window);connection.use_proxy.setChecked(True);connection.link.setPlainText('vless://eb799b6d-443f-4540-9f56-333221145321@example.com:443?security=tls&type=ws&path=%2Fvpn#Preview')
        self.assertTrue(connection.save_button.isEnabled());connection.save()
        self.wait(lambda:self.window.config['settings']['source']!='warp')
        routing=RoutingDialog(self.window);routing.enable.setChecked(True);routing.apply()
        self.wait(lambda:bool(self.window.config['settings'].get('routes')))
        stored=desktop.rpc(self.socket,'get_config',demo=True);self.assertEqual(stored['settings']['routes'][0]['kind'],'geoip')
        reopened=ConnectionDialog(self.window);self.assertTrue(reopened.link.toPlainText().startswith('vless://'))
        reopened.dns.setText('127.0.0.1');reopened.save();self.wait(lambda:not reopened.loading)
        self.assertNotEqual(self.window.config['settings']['dns'],'127.0.0.1')
        reopened.dns.setText('9.9.9.9');self.assertTrue(reopened.save_button.isEnabled());reopened.save();self.wait(lambda:self.window.config['settings']['dns']=='9.9.9.9')
        self.window.preferences.set_autostart(True);self.assertTrue(self.window.preferences.autostart_path().exists());self.window.preferences.set_autostart(False);self.assertFalse(self.window.preferences.autostart_path().exists())


if __name__ == '__main__':
    unittest.main()
