"""Amber - a display color app (PyQt6, Windows).

Run:   pip install PyQt6  &&  python amber.py
Build: pip install pyinstaller  &&  pyinstaller --onefile --noconsole --name Amber amber.py
"""
import base64, ctypes, json, os, sys
from ctypes import wintypes
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QSlider,
                             QPushButton, QListWidget, QListWidgetItem, QFrame, QInputDialog, QMessageBox,
                             QCheckBox, QPlainTextEdit, QDialog, QDialogButtonBox)

IS_WIN = sys.platform == "win32"
DATA = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Amber")
PRESET_FILE = os.path.join(DATA, "presets.json")

# key: (label, min, max, neutral, hint)
PARAMS = {
    "saturation": ("Saturation", 0, 200, 100, "Grayscale to vivid"),
    "vibrance": ("Vibrance", 0, 200, 100, "Boosts muted colors more than vivid ones"),
    "brightness": ("Brightness", -50, 50, 0, "Lift or lower the image"),
    "contrast": ("Contrast", 50, 150, 100, "Separation between light and dark"),
    "gamma": ("Gamma", 50, 200, 100, "Midtone curve"),
    "temperature": ("Temperature", -100, 100, 0, "Cooler blue to warmer amber"),
    "tint": ("Tint", -100, 100, 0, "Green to magenta"),
}
NEUTRAL = {k: v[3] for k, v in PARAMS.items()}
BUILTIN = {
    "Balanced": {**NEUTRAL, "saturation": 110, "contrast": 105},
    "Vivid": {**NEUTRAL, "saturation": 150, "vibrance": 140, "contrast": 110},
    "Forest": {**NEUTRAL, "saturation": 125, "temperature": -15, "tint": -10, "gamma": 95},
    "Desert": {**NEUTRAL, "saturation": 120, "temperature": 30, "brightness": 4},
    "Snow": {**NEUTRAL, "brightness": -6, "contrast": 115, "temperature": -20},
    "Night": {**NEUTRAL, "brightness": -12, "temperature": 40, "saturation": 90},
}


# ---------------------------------------------------------------- engine
def _mul(a, b):
    return [[sum(a[i][k] * b[k][j] for k in range(5)) for j in range(5)] for i in range(5)]


def build_matrix(v):
    s = v["saturation"] / 100.0
    vib = v["vibrance"] / 100.0
    s *= vib ** 0.5  # approximation: true vibrance is driver-specific
    lr, lg, lb = 0.2126, 0.7152, 0.0722
    # row-vector convention: out_c = sum_r in_r * M[r][c]; luminance weight belongs to the input row
    sat = [[(lr, lg, lb)[r] * (1 - s) + (s if r == c else 0) for c in range(3)] + [0, 0] for r in range(3)] + [[0, 0, 0, 1, 0], [0, 0, 0, 0, 1]]
    t = v["temperature"] / 100.0
    tn = v["tint"] / 100.0
    wb = [[1 + 0.25 * t, 0, 0, 0, 0], [0, 1 - 0.20 * tn, 0, 0, 0], [0, 0, 1 - 0.25 * t, 0, 0], [0, 0, 0, 1, 0], [0, 0, 0, 0, 1]]
    c = v["contrast"] / 100.0
    b = v["brightness"] / 100.0
    cb = [[c, 0, 0, 0, 0], [0, c, 0, 0, 0], [0, 0, c, 0, 0], [0, 0, 0, 1, 0], [0.5 * (1 - c) + b, 0.5 * (1 - c) + b, 0.5 * (1 - c) + b, 0, 1]]
    return _mul(_mul(sat, wb), cb)


class Engine:
    """Applies a color matrix via the Windows Magnification API and gamma via the gamma ramp."""

    def __init__(self):
        self.ok = False
        self.error = ""
        if not IS_WIN:
            self.error = "Preview mode: display control works on Windows only."
            return
        try:
            self.mag = ctypes.WinDLL("magnification.dll")
            self.mag.MagInitialize.restype = wintypes.BOOL
            self.mag.MagSetFullscreenColorEffect.argtypes = [ctypes.POINTER(ctypes.c_float * 25)]
            self.mag.MagSetFullscreenColorEffect.restype = wintypes.BOOL
            self.ok = bool(self.mag.MagInitialize())
            self.gdi, self.user = ctypes.WinDLL("gdi32"), ctypes.WinDLL("user32")
            self.user.GetDC.restype = wintypes.HDC
            self.user.GetDC.argtypes = [wintypes.HWND]
            self.user.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
            self.gdi.SetDeviceGammaRamp.argtypes = [wintypes.HDC, ctypes.c_void_p]
        except Exception as e:  # pragma: no cover
            self.error = str(e)

    def apply(self, v):
        if not self.ok:
            return False
        m = build_matrix(v)
        arr = (ctypes.c_float * 25)(*[m[i][j] for i in range(5) for j in range(5)])
        good = bool(self.mag.MagSetFullscreenColorEffect(ctypes.byref(arr)))
        self._gamma(v["gamma"] / 100.0)
        return good

    def _gamma(self, g):
        ramp = (ctypes.c_ushort * 768)()
        for i in range(256):
            val = int(min(65535, ((i / 255.0) ** (1.0 / g)) * 65535))
            ramp[i] = ramp[256 + i] = ramp[512 + i] = val
        hdc = self.user.GetDC(None)
        self.gdi.SetDeviceGammaRamp(hdc, ctypes.byref(ramp))
        self.user.ReleaseDC(None, hdc)

    def reset(self):
        if self.ok:
            self.apply(NEUTRAL)

    def close(self):
        if self.ok:
            self.reset()
            self.mag.MagUninitialize()


# ---------------------------------------------------------------- storage
def load_custom():
    try:
        with open(PRESET_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_custom(d):
    try:
        os.makedirs(DATA, exist_ok=True)
        with open(PRESET_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
    except Exception:
        pass


def encode(name, vals):
    return "AMBER1-" + base64.urlsafe_b64encode(json.dumps({"n": name, "v": vals}).encode()).decode()


def decode(code):
    p = json.loads(base64.urlsafe_b64decode(code.strip()[len("AMBER1-"):].encode()))
    vals = {k: max(PARAMS[k][1], min(PARAMS[k][2], int(p["v"].get(k, PARAMS[k][3])))) for k in PARAMS}
    return str(p["n"])[:40], vals


# ---------------------------------------------------------------- UI
QSS = """
* { font-family: 'Segoe UI Variable Text','Segoe UI','Inter',sans-serif; font-size: 13px; color: #F1F1F8; }
QWidget#root { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #08080D, stop:1 #1A1208); }
QFrame#rail { background: rgba(0,0,0,90); border-right: 1px solid rgba(255,255,255,24); }
QFrame#card { background: rgba(255,255,255,14); border: 1px solid rgba(255,255,255,30); border-radius: 16px; }
QLabel { background: transparent; }
QLabel#h1 { font-size: 22px; font-weight: 700; }
QLabel#eyebrow { color: #FFB020; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
QLabel#dim { color: #8C8CA6; font-size: 12px; }
QLabel#big { font-size: 40px; font-weight: 300; }
QLabel#val { font-size: 13px; font-weight: 600; color: #F1F1F8; }
QPushButton { background: rgba(255,255,255,18); border: 1px solid rgba(255,255,255,34); border-radius: 9px; padding: 8px 14px; }
QPushButton:hover { background: rgba(255,255,255,34); }
QPushButton:pressed { background: rgba(255,255,255,50); }
QPushButton#primary { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #FFB020, stop:1 #F27A00); border: none; font-weight: 600; color: #1A1208; }
QPushButton#primary:hover { background: #FFC24D; }
QPushButton#nav { border: none; background: transparent; font-size: 17px; padding: 10px; border-radius: 11px; }
QPushButton#nav:checked { background: rgba(255,167,38,70); }
QPushButton#nav:hover { background: rgba(255,255,255,26); }
QSlider::groove:horizontal { height: 4px; background: rgba(255,255,255,50); border-radius: 2px; }
QSlider::sub-page:horizontal { background: #FFA726; border-radius: 2px; }
QSlider::handle:horizontal { background: #fff; width: 14px; height: 14px; margin: -5px 0; border-radius: 7px; border: 3px solid #FFA726; }
QListWidget { background: transparent; border: none; outline: 0; }
QListWidget::item { background: rgba(255,255,255,10); border: 1px solid transparent; border-radius: 10px; padding: 10px 12px; margin-bottom: 6px; }
QListWidget::item:hover { background: rgba(255,255,255,24); }
QListWidget::item:selected { background: rgba(255,167,38,70); border: 1px solid rgba(255,176,32,160); color: white; }
QCheckBox::indicator { width: 36px; height: 20px; border-radius: 10px; background: rgba(255,255,255,60); }
QCheckBox::indicator:checked { background: #FFA726; }
QPlainTextEdit { background: rgba(0,0,0,110); border: 1px solid rgba(255,255,255,34); border-radius: 8px; }
QDialog, QMessageBox, QInputDialog { background: #14141D; }
"""


class Row(QWidget):
    def __init__(self, key, on_change, big=False):
        super().__init__()
        self.key, self.on_change = key, on_change
        label, lo, hi, neutral, hint = PARAMS[key]
        self.neutral = neutral
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        top = QHBoxLayout()
        name = QLabel(label)
        name.setToolTip(hint)
        self.val = QLabel()
        self.val.setObjectName("big" if big else "val")
        top.addWidget(name)
        top.addStretch()
        if not big:
            top.addWidget(self.val)
        lay.addLayout(top)
        if big:
            lay.addWidget(self.val)
        self.s = QSlider(Qt.Orientation.Horizontal)
        self.s.setRange(lo, hi)
        self.s.setValue(neutral)
        self.s.setToolTip(hint + "  (double-click to reset)")
        self.s.valueChanged.connect(self._changed)
        self.s.mouseDoubleClickEvent = lambda e: self.s.setValue(self.neutral)
        lay.addWidget(self.s)
        self._fmt()

    def _fmt(self):
        v = self.s.value()
        self.val.setText(f"{v}%" if self.neutral == 100 else f"{v:+d}" if v else "0")

    def _changed(self, _):
        self._fmt()
        self.on_change()

    def set(self, v):
        self.s.blockSignals(True)
        self.s.setValue(v)
        self.s.blockSignals(False)
        self._fmt()


class Main(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle("Amber")
        self.resize(1180, 760)
        self.setMinimumSize(980, 640)
        self.engine = Engine()
        self.custom = load_custom()
        self.on = False
        self.timer = QTimer(self, singleShot=True, interval=60, timeout=self._push)
        self._build()
        self._fill_presets()
        self._status()

    # ----- layout
    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        rail = QFrame(objectName="rail")
        rail.setFixedWidth(72)
        rl = QVBoxLayout(rail)
        rl.setContentsMargins(10, 16, 10, 16)
        logo = QLabel("A")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFixedSize(36, 36)
        logo.setStyleSheet("background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #FFB020,stop:1 #F27A00);border-radius:11px;font-weight:800;font-size:18px;color:#1A1208")
        rl.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)
        rl.addSpacing(18)
        nav = QPushButton("◐", objectName="nav", checkable=True, checked=True, toolTip="Display")
        rl.addWidget(nav)
        rl.addStretch()
        about = QPushButton("?", objectName="nav", toolTip="About", clicked=self._about)
        rl.addWidget(about)
        root.addWidget(rail)

        mid = QVBoxLayout()
        mid.setContentsMargins(32, 26, 20, 22)
        mid.setSpacing(16)
        head = QHBoxLayout()
        col = QVBoxLayout()
        col.setSpacing(0)
        col.addWidget(QLabel("DISPLAY", objectName="eyebrow"))
        self.title = QLabel("Custom look", objectName="h1")
        col.addWidget(self.title)
        head.addLayout(col)
        head.addStretch()
        self.live = QCheckBox("Live adjust")
        self.live.setChecked(True)
        head.addWidget(self.live)
        mid.addLayout(head)
        mid.addWidget(QLabel("Presets are starting points. Every slider works whatever you play.", objectName="dim"))

        self.rows = {}
        top = QHBoxLayout()
        top.setSpacing(16)
        for k in ("saturation", "vibrance"):
            card = QFrame(objectName="card")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(22, 16, 22, 18)
            self.rows[k] = Row(k, self._changed, big=True)
            cl.addWidget(self.rows[k])
            top.addWidget(card)
        mid.addLayout(top)

        fine = QFrame(objectName="card")
        fl = QVBoxLayout(fine)
        fl.setContentsMargins(22, 16, 22, 20)
        fl.addWidget(QLabel("Fine tune"))
        fl.addWidget(QLabel("Brightness, contrast and gamma change how the whole screen looks, not just games.", objectName="dim"))
        fl.addSpacing(8)
        grid = QGridLayout()
        grid.setHorizontalSpacing(36)
        grid.setVerticalSpacing(18)
        for i, k in enumerate(("brightness", "gamma", "contrast", "temperature", "tint")):
            self.rows[k] = Row(k, self._changed)
            grid.addWidget(self.rows[k], i // 2, i % 2)
        fl.addLayout(grid)
        mid.addWidget(fine)
        mid.addStretch()

        bar = QFrame(objectName="card")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(20, 12, 16, 12)
        self.dot = QLabel("●")
        self.status = QLabel("Off")
        self.detail = QLabel("", objectName="dim")
        txt = QVBoxLayout()
        txt.setSpacing(0)
        txt.addWidget(self.status)
        txt.addWidget(self.detail)
        bl.addWidget(self.dot)
        bl.addLayout(txt)
        bl.addStretch()
        reset = QPushButton("Reset", clicked=self.reset)
        self.toggle = QPushButton("Turn on", objectName="primary", clicked=self.flip)
        self.toggle.setMinimumWidth(110)
        bl.addWidget(reset)
        bl.addWidget(self.toggle)
        mid.addWidget(bar)
        root.addLayout(mid, 1)

        side = QFrame(objectName="card")
        side.setFixedWidth(310)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(16, 16, 16, 16)
        sl.addWidget(QLabel("Scene presets"))
        self.list = QListWidget()
        self.list.itemClicked.connect(self._pick)
        sl.addWidget(self.list, 1)
        sl.addWidget(QPushButton("Save look…", objectName="primary", clicked=self.save_look))
        r = QHBoxLayout()
        r.addWidget(QPushButton("Delete", clicked=self.delete_look))
        r.addWidget(QPushButton("Import", clicked=self.import_code))
        r.addWidget(QPushButton("Share", clicked=self.share_code))
        sl.addLayout(r)
        wrap = QVBoxLayout()
        wrap.setContentsMargins(0, 26, 28, 22)
        wrap.addWidget(side)
        root.addLayout(wrap)

    # ----- behavior
    def values(self):
        return {k: r.s.value() for k, r in self.rows.items()}

    def _changed(self):
        self.title.setText("Custom look")
        self.list.clearSelection()
        if self.on and self.live.isChecked():
            self.timer.start()

    def _push(self):
        ok = self.engine.apply(self.values())
        self._status(None if ok else (self.engine.error or "Could not apply"))

    def flip(self):
        self.on = not self.on
        if self.on:
            self._push()
        else:
            self.engine.reset()
        self._status()

    def reset(self):
        for k, r in self.rows.items():
            r.set(NEUTRAL[k])
        self.title.setText("Custom look")
        self.list.clearSelection()
        self.engine.reset()
        self.on = False
        self._status()

    def _status(self, err=None):
        c = "#FFA726" if self.on and not err else "#74748C"
        self.dot.setStyleSheet(f"color:{c};font-size:12px")
        self.status.setText("Look is on" if self.on else "Off")
        self.detail.setText(err or ("Applied to your desktop" if self.on else (self.engine.error or "Your original colors are showing")))
        self.toggle.setText("Turn off" if self.on else "Turn on")

    def _all(self):
        return {**BUILTIN, **self.custom}

    def _fill_presets(self):
        self.list.clear()
        for n, v in self._all().items():
            it = QListWidgetItem(f"{n}\nSaturation {v['saturation']}%  ·  Contrast {v['contrast']}%")
            it.setData(Qt.ItemDataRole.UserRole, n)
            self.list.addItem(it)

    def _pick(self, it):
        n = it.data(Qt.ItemDataRole.UserRole)
        for k, r in self.rows.items():
            r.set(self._all()[n][k])
        self.title.setText(n)
        if self.on:
            self._push()

    def save_look(self):
        n, ok = QInputDialog.getText(self, "Save look", "Name:")
        n = n.strip()[:40]
        if ok and n:
            self.custom[n] = self.values()
            save_custom(self.custom)
            self._fill_presets()

    def delete_look(self):
        it = self.list.currentItem()
        n = it.data(Qt.ItemDataRole.UserRole) if it else None
        if n in self.custom:
            del self.custom[n]
            save_custom(self.custom)
            self._fill_presets()
        elif n:
            QMessageBox.information(self, "Amber", "Built-in scenes can't be deleted.")

    def share_code(self):
        code = encode(self.title.text(), self.values())
        QApplication.clipboard().setText(code)
        QMessageBox.information(self, "Copied", "Share code copied. Paste it wherever you share looks.")

    def import_code(self):
        d = QDialog(self)
        d.setWindowTitle("Import look")
        lay = QVBoxLayout(d)
        lay.addWidget(QLabel("Paste a share code (starts with AMBER1-):"))
        box = QPlainTextEdit()
        lay.addWidget(box)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        d.resize(460, 240)
        if d.exec():
            try:
                n, v = decode(box.toPlainText())
                self.custom[n] = v
                save_custom(self.custom)
                self._fill_presets()
            except Exception:
                QMessageBox.warning(self, "Import", "That share code isn't valid.")

    def _about(self):
        QMessageBox.information(self, "Amber", "Turn on a look to apply it to your desktop. Closing the app restores your display.\nWorks on the desktop and borderless/windowed games, not exclusive fullscreen or HDR.")

    def closeEvent(self, e):
        self.engine.close()
        super().closeEvent(e)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = Main()
    w.show()
    if "--shot" in sys.argv:
        w.rows["saturation"].set(100)
        w.list.setCurrentRow(1)
        w._pick(w.list.item(1))
        w.on = True
        w._status()
        QTimer.singleShot(300, lambda: (w.grab().save(sys.argv[sys.argv.index("--shot") + 1]), app.quit()))
    sys.exit(app.exec())
