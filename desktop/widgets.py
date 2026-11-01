"""Windows Zarp drawing geometry and colours translated to Qt."""
from __future__ import annotations
import math
from pathlib import Path
from PySide6.QtCore import Qt,QRectF,QPointF,QTimer,Signal,QVariantAnimation,QEasingCurve
from PySide6.QtGui import QColor,QFont,QFontDatabase,QPainter,QPainterPath,QPen,QIcon,QPixmap,QPolygonF,QPalette
from PySide6.QtWidgets import QApplication,QAbstractButton,QPushButton,QWidget,QLabel,QMenu,QCheckBox,QSpinBox,QStyledItemDelegate,QComboBox

BACK='#121419';PANEL='#1b1e25';HOVER='#252932';BORDER='#2e323c';TEXT='#c4c8d0';DIM='#808692';DISABLED='#4e535e';ACCENT='#f48120';BUSY='#5096ff';OK='#40c478';BAD='#e85454';OFF='#464b58'
FAMILY='Noto Sans'

def init_theme(app):
    global FAMILY
    fonts=Path(__file__).resolve().parents[1]/'resources/fonts'
    for path in fonts.glob('*.ttf'):QFontDatabase.addApplicationFont(str(path))
    # Use an existing local Windows font for faithful WSL previews; never redistribute it.
    for name in ('segoeui.ttf','segoeuib.ttf','seguisb.ttf','msyh.ttc'):
        path=Path('/mnt/c/Windows/Fonts')/name
        if path.is_file():QFontDatabase.addApplicationFont(str(path))
    families=QFontDatabase.families()
    FAMILY=next((f for f in ('Segoe UI','Selawik','Noto Sans','DejaVu Sans') if f in families),'Sans Serif')
    app.setStyle('Fusion');app.setFont(font(9));app.setStyleSheet(STYLE)

def font(points=9.5,bold=False):
    f=QFont(FAMILY);f.setPixelSize(math.ceil(points*96/72));f.setWeight(QFont.Weight.Bold if bold else QFont.Weight.Normal);return f

def label(parent,text,x,y,w,h=20,size=9.5,color=TEXT,bold=False,wrap=False):
    item=QLabel(text,parent);item.setFont(font(size,bold));item.setStyleSheet('color:'+color+'; background:transparent;');item.setGeometry(x,y,w,h);item.setWordWrap(wrap);return item

def button(parent,text,x,y,w=120,primary=False,callback=None):
    b=QPushButton(text,parent);b.setGeometry(x,y,w,34);b.setFont(font(9));b.setProperty('primary',primary);b.setCursor(Qt.CursorShape.PointingHandCursor)
    if callback:b.clicked.connect(callback)
    return b

def app_icon(color=ACCENT):
    pix=QPixmap(64,64);pix.fill(Qt.GlobalColor.transparent);p=QPainter(pix);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor(color));p.drawEllipse(QRectF(2,2,60,60));p.setBrush(Qt.GlobalColor.white);p.drawPolygon(QPolygonF([QPointF(x*2,y*2) for x,y in ((18,5),(9,18),(15,18),(13,27),(23,13),(17,13))]));p.end();return QIcon(pix)

class PowerButton(QAbstractButton):
    def __init__(self,parent=None):
        super().__init__(parent);self.setFixedSize(200,200);self.setCursor(Qt.CursorShape.PointingHandCursor);self.setFocusPolicy(Qt.FocusPolicy.StrongFocus);self.state='off';self.angle=0.;self.timer=QTimer(self);self.timer.setInterval(16);self.timer.timeout.connect(self.advance)
    def advance(self):self.angle=(self.angle+5)%360;self.update()
    def set_state(self,state):
        if state!=self.state:self.state=state;self.timer.start() if state=='busy' else self.timer.stop();self.update()
    def enterEvent(self,e):self.update();super().enterEvent(e)
    def leaveEvent(self,e):self.update();super().leaveEvent(e)
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.fillRect(self.rect(),QColor(BACK));size=min(self.width(),self.height())-8;rc=QRectF((self.width()-size)/2,(self.height()-size)/2,size,size);ring=size*.055;colour=QColor(ACCENT if self.state=='on' else BUSY if self.state=='busy' else OFF)
        if self.state=='on':
            for i in range(6,0,-1):
                c=QColor(ACCENT);c.setAlpha(14);p.setPen(QPen(c,i*2));p.setBrush(Qt.BrushStyle.NoBrush);delta=-ring+i*1.5;p.drawEllipse(rc.adjusted(-delta,-delta,delta,delta))
        ringrc=rc.adjusted(ring/2,ring/2,-ring/2,-ring/2);base=QColor(colour);base.setAlpha(60 if self.state=='busy' else 255);p.setPen(QPen(base,ring));p.setBrush(Qt.BrushStyle.NoBrush);p.drawEllipse(ringrc)
        if self.state=='busy':
            pen=QPen(colour,ring);pen.setCapStyle(Qt.PenCapStyle.RoundCap);p.setPen(pen);p.drawArc(ringrc,int(-self.angle*16),-90*16)
        disc=rc.adjusted(ring*2.2,ring*2.2,-ring*2.2,-ring*2.2);p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor(BORDER if self.isDown() else HOVER if self.underMouse() else PANEL));p.drawEllipse(disc)
        icon=disc.width()*.36;ic=QRectF(disc.x()+(disc.width()-icon)/2,disc.y()+(disc.height()-icon)/2+icon*.04,icon,icon);pen=QPen(QColor(ACCENT if self.state=='on' else BUSY if self.state=='busy' else DIM),icon*.11);pen.setCapStyle(Qt.PenCapStyle.RoundCap);p.setPen(pen);p.setBrush(Qt.BrushStyle.NoBrush);p.drawArc(ic,60*16,-300*16);p.drawLine(QPointF(ic.center().x(),ic.y()-icon*.12),QPointF(ic.center().x(),ic.y()+ic.height()*.42))
        if self.hasFocus() and not self.underMouse():
            pen=QPen(QColor(DIM),1,Qt.PenStyle.DotLine);p.setPen(pen);p.drawEllipse(disc.adjusted(8,8,-8,-8))

class IconButton(QAbstractButton):
    def __init__(self,kind,parent=None):
        super().__init__(parent);self.kind=kind;self.setFixedSize(40,40);self.setCursor(Qt.CursorShape.PointingHandCursor);self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    def enterEvent(self,e):self.update();super().enterEvent(e)
    def leaveEvent(self,e):self.update();super().leaveEvent(e)
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setPen(QPen(QColor(BORDER),1));p.setBrush(QColor(HOVER if self.underMouse() else PANEL));p.drawRoundedRect(QRectF(.5,.5,39,39),9,9);p.setPen(QPen(QColor(TEXT),1.6));p.setBrush(Qt.BrushStyle.NoBrush)
        if self.kind=='language':
            p.drawEllipse(QRectF(11,11,18,18));p.drawEllipse(QRectF(16,11,8,18));p.drawLine(QPointF(11,20),QPointF(29,20));p.drawLine(QPointF(13,15),QPointF(27,15));p.drawLine(QPointF(13,25),QPointF(27,25))
        else:
            path=QPainterPath()
            for i in range(64):
                angle=i*math.pi/32;r=9 if i%8 in (1,2,3,4) else 7.1;point=QPointF(20+math.cos(angle)*r,20+math.sin(angle)*r);path.moveTo(point) if i==0 else path.lineTo(point)
            path.closeSubpath();p.drawPath(path);p.drawEllipse(QRectF(16.6,16.6,6.8,6.8))

class Toggle(QCheckBox):
    def __init__(self,text='',parent=None):
        super().__init__(text,parent);self.setFont(font());self.setFixedHeight(28);self.setCursor(Qt.CursorShape.PointingHandCursor);self.position=0.;self.animation=QVariantAnimation(self);self.animation.setDuration(110);self.animation.valueChanged.connect(self.frame);self.toggled.connect(self.animate)
    def frame(self,value):self.position=float(value);self.update()
    def animate(self,checked):
        self.animation.stop();self.animation.setStartValue(self.position);self.animation.setEndValue(1. if checked else 0.);self.animation.start()
    def hitButton(self,pos):return self.rect().contains(pos)
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);track=QRectF(.5,(self.height()-20)/2,36,20);p.setPen(Qt.PenStyle.NoPen);p.setBrush(QColor(ACCENT if self.isChecked() else OFF) if self.isEnabled() else QColor(BORDER));p.drawRoundedRect(track,10,10);p.setBrush(QColor('#faf6f2' if self.isChecked() else TEXT));p.drawEllipse(QRectF(3.7+self.position*16,track.y()+3.2,13.6,13.6));p.setPen(QColor(TEXT if self.isEnabled() else DISABLED));p.setFont(self.font());p.drawText(self.rect().adjusted(55,0,0,0),Qt.AlignmentFlag.AlignVCenter,self.text())

class NumberBox(QWidget):
    valueChanged=Signal(int)
    def __init__(self,parent=None,minimum=1,maximum=100):
        super().__init__(parent);self.setFixedSize(116,32);self._value=minimum;self.minimum=minimum;self.maximum=maximum;self.hover=0;self.setMouseTracking(True);self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    def value(self):return self._value
    def setValue(self,v):
        v=max(self.minimum,min(self.maximum,int(v)))
        if v!=self._value:self._value=v;self.update();self.valueChanged.emit(v)
    def mouseMoveEvent(self,e):self.hover=-1 if e.position().x()<34 else 1 if e.position().x()>82 else 0;self.update()
    def leaveEvent(self,e):self.hover=0;self.update()
    def mousePressEvent(self,e):
        if e.button()==Qt.MouseButton.LeftButton:self.setValue(self._value+(-1 if e.position().x()<34 else 1 if e.position().x()>82 else 0))
    def keyPressEvent(self,e):
        if e.key() in (Qt.Key.Key_Up,Qt.Key.Key_Right,Qt.Key.Key_Plus):self.setValue(self._value+1)
        elif e.key() in (Qt.Key.Key_Down,Qt.Key.Key_Left,Qt.Key.Key_Minus):self.setValue(self._value-1)
        else:super().keyPressEvent(e)
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setPen(QPen(QColor(BORDER),1));p.setBrush(QColor(PANEL));p.drawRoundedRect(QRectF(.5,.5,115,31),8,8);p.drawLine(33,6,33,26);p.drawLine(83,6,83,26);p.setPen(QPen(QColor(TEXT if self.isEnabled() else DISABLED),1.6));p.drawLine(12,16,23,16);p.drawLine(94,16,105,16);p.drawLine(99,11,99,21);p.setFont(font(9));p.drawText(self.rect(),Qt.AlignmentFlag.AlignCenter,str(self._value))

class StatusColorDelegate(QStyledItemDelegate):
    def initStyleOption(self,option,index):
        super().initStyleOption(option,index)
        foreground=index.data(Qt.ItemDataRole.ForegroundRole)
        if foreground is not None:option.palette.setBrush(QPalette.ColorRole.HighlightedText,foreground)

class DarkSelect(QComboBox):
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setPen(QPen(QColor(BORDER),1));p.setBrush(QColor(HOVER if self.underMouse() else PANEL));p.drawRoundedRect(QRectF(.5,.5,self.width()-1,self.height()-1),9,9);p.setPen(QColor(TEXT if self.isEnabled() else DISABLED));p.setFont(font(9));p.drawText(self.rect().adjusted(12,0,-30,0),Qt.AlignmentFlag.AlignVCenter,self.currentText());p.setPen(QPen(QColor(DIM),1));x=self.width()-18;y=self.height()/2;p.drawPolyline(QPolygonF([QPointF(x-4,y-2),QPointF(x,y+2),QPointF(x+4,y-2)]))

class MenuButton(QPushButton):
    def paintEvent(self,event):
        super().paintEvent(event);p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setPen(QPen(QColor(DIM),1));x=self.width()-18;y=self.height()/2;p.drawPolyline(QPolygonF([QPointF(x-4,y-2),QPointF(x,y+2),QPointF(x+4,y-2)]))

STYLE='''
QWidget {background:#121419;color:#c4c8d0;}
QToolTip {background:#252932;color:#c4c8d0;border:1px solid #404551;padding:6px;}
QPushButton {background:#1b1e25;border:1px solid #2e323c;border-radius:9px;padding:0 10px;min-height:30px;}
QPushButton:hover {background:#252932;border-color:#404551;}
QPushButton:pressed {background:#2e323c;}
QPushButton:disabled {background:#121419;color:#4e535e;}
QPushButton[primary="true"] {background:#f48120;color:#1e140c;border-color:#f48120;}
QPushButton[primary="true"]:hover {background:#fa963f;}
QPushButton[primary="true"]:disabled {background:#121419;color:#4e535e;border-color:#2e323c;}
QLineEdit,QPlainTextEdit {background:#1b1e25;border:1px solid #2e323c;border-radius:9px;padding:6px 9px;selection-background-color:#454d5a;}
QLineEdit:focus,QPlainTextEdit:focus {border-color:#404551;}
QComboBox {background:#1b1e25;border:1px solid #2e323c;border-radius:9px;padding:6px 12px;min-height:18px;}
QComboBox::drop-down {border:0;width:27px;}
QComboBox::down-arrow {image:none;border-left:4px solid transparent;border-right:4px solid transparent;border-top:4px solid #808692;}
QComboBox QAbstractItemView {background:#1b1e25;border:1px solid #2e323c;selection-background-color:#252932;outline:0;padding:3px;}
QComboBox QAbstractItemView::item {min-height:30px;}
QTableWidget {background:#1b1e25;border:0;gridline-color:#2e323c;selection-background-color:#252932;outline:0;}
QTableWidget::item {padding:0 1px;border:0;border-right:1px solid #343943;}
QHeaderView::section {background:#121419;color:#808692;border:0;border-bottom:1px solid #2e323c;padding:4px 6px;}
QTableCornerButton::section {background:#121419;border:0;}
QScrollBar:vertical {background:#1b1e25;width:14px;margin:0;}
QScrollBar::handle:vertical {background:#464b58;min-height:24px;border:4px solid #1b1e25;border-radius:6px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;}
QScrollBar:horizontal {background:#1b1e25;height:10px;}
QScrollBar::handle:horizontal {background:#464b58;min-width:24px;}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {width:0;}
QMenu {background:#1b1e25;border:1px solid #2e323c;padding:3px;}
QMenu::item {padding:7px 14px 7px 26px;min-width:150px;}
QMenu::item:selected {background:#252932;border-radius:5px;}
QMenu::separator {height:1px;background:#2e323c;margin:4px 0;}
QCheckBox {spacing:10px;}
QCheckBox::indicator {width:16px;height:16px;border:1px solid #808692;border-radius:3px;}
QCheckBox::indicator:checked {background:#f48120;border-color:#f48120;}
QProgressBar {background:#1b1e25;border:0;min-height:4px;max-height:4px;}
QProgressBar::chunk {background:#5096ff;}
'''
