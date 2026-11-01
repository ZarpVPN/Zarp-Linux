import json,socket
from PySide6.QtCore import QObject,QRunnable,Signal,Slot

def rpc(path,command,params=None,demo=False):
    request=json.dumps({'version':1,'command':command,'params':params or {},'demo':demo},ensure_ascii=False).encode()+b'\n'
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(240);client.connect(path);client.sendall(request)
        with client.makefile('rb') as reader:data=reader.readline(8*1024*1024+1)
    if len(data)>8*1024*1024:raise RuntimeError('Response exceeds limit')
    response=json.loads(data)
    if response.get('version')!=1 or not response.get('ok'):raise RuntimeError(response.get('error','Invalid service response'))
    return response.get('result')

class Signals(QObject):
    result=Signal(object);error=Signal(str)
class Job(QRunnable):
    def __init__(self,function,parent=None):
        super().__init__();self.setAutoDelete(False);self.function=function;self.signals=Signals(parent)
    def run(self):
        try:self.signals.result.emit(self.function())
        except OSError:self.signals.error.emit('service')
        except Exception as error:self.signals.error.emit(str(error))
class Reply(QObject):
    def __init__(self,window,job,success,failure):super().__init__(window);self.window,self.job,self.success,self.failure=window,job,success,failure
    @Slot(object)
    def done(self,value):
        try:
            if self.success:self.success(value)
        finally:self.release()
    @Slot(str)
    def fail(self,value):
        try:
            if self.failure:self.failure(value)
        finally:self.release()
    def release(self):
        self.window.finish_job(self.job)
        self.job=None;self.success=None;self.failure=None;self.window=None;self.deleteLater()
