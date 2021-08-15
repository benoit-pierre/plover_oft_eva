from functools import wraps
from pathlib import Path
from queue import Queue
from time import time
import functools
import logging
import re
import threading

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from serial import Serial
from serial.tools.list_ports import comports

from .machine import OftEvaConnection, OftEvaMachine, ReadTimeout


def setup_serial(log, dev):
    serial_ports = [x[0] for x in comports()]
    log.info('serial ports: %r', serial_ports)
    serial_params = OftEvaMachine.SERIAL_PARAMS
    if dev is None:
        serial_params['port'] = serial_ports[0]
    else:
        serial_params['port'] = dev
    log.info('serial params: %r', serial_params)
    return Serial(**serial_params)

def iter_strokes_until_elapsed(ctrl, cxn, duration, max_strokes=None):
    assert max_strokes is None or max_strokes > 0
    start = time()
    while not ctrl.stopped and (time() - start) < duration:
        try:
            stroke = cxn.read_stroke()
        except ReadTimeout:
            continue
        yield stroke
        if max_strokes is not None:
            max_strokes -= 1
            if not max_strokes:
                break
    if ctrl.stopped:
        raise EOFError

def with_standard_handshakes(f):
    @wraps(f)
    def w(ctrl, log, cxn):
        cxn.opening_handshake()
        f(ctrl, log, cxn)
        cxn.reset_input_buffer()
        cxn.closing_handshake()
    return w

def test_beep_command(ctrl, log, cxn):
    cxn.send_receive(b'\x17\x07\xd0\x00\x50\x00\x96', 1, b'\x06')
    ctrl.question('Did you hear a beep?')

@with_standard_handshakes
def test_strokes_reporting(ctrl, log, cxn):
    ctrl.information('Please enter a few (5) strokes to ensure everything is working correctly.')
    for stroke in iter_strokes_until_elapsed(ctrl, cxn, 10, 5):
        log.debug('stroke: %s', stroke)
    ctrl.information('Strokes reporting will now be disabled, please try again.')
    cxn.reset_input_buffer()
    cxn.toggle_strokes(False)
    for stroke in iter_strokes_until_elapsed(ctrl, cxn, 10, 5):
        log.debug('stroke: %s', stroke)
    ctrl.information('Re-enabling strokes reporting, please try again.')
    cxn.reset_input_buffer()
    cxn.toggle_strokes(True)
    for stroke in iter_strokes_until_elapsed(ctrl, cxn, 10, 5):
        log.debug('stroke: %s', stroke)

TEST_LIST = (
    ('Test beep command', test_beep_command),
)

class Controller(QtCore.QObject):

    requested = QtCore.pyqtSignal(str, tuple)

    def __init__(self):
        super().__init__()
        self._stop = threading.Event()
        self._reply = Queue()

    def _cmd(self, cmd, *args):
        self.requested.emit(cmd, args)
        return self._reply.get()

    def prompt(self, text):
        return self._cmd('prompt', text)

    def information(self, text):
        return self._cmd('information', text)

    def question(self, text):
        return self._cmd('question', text)

    def reply(self, result):
        self._reply.put(result)

    def stop(self):
        self._stop.set()

    @property
    def stopped(self):
        return self._stop.is_set()

    def reset(self):
        self._stop.clear()


class Console(QtWidgets.QPlainTextEdit):

    def __init__(self, parent=None):
        super().__init__(parent)
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Base, Qt.black)
        palette.setColor(QtGui.QPalette.Text, Qt.lightGray)
        self.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.setPalette(palette)
        self._std_fmt = QtGui.QTextCharFormat()
        self._info_fmt = QtGui.QTextCharFormat()
        self._info_fmt.setForeground(Qt.lightGray)
        self._warn_fmt = QtGui.QTextCharFormat()
        self._warn_fmt.setForeground(Qt.yellow)
        self._err_fmt = QtGui.QTextCharFormat()
        self._err_fmt.setForeground(Qt.red)
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def print(self, s, end='\n'):
        self.log(logging.DEBUG, s, end=end)

    def log(self, level, s, end='\n'):
        scrollbar = self.verticalScrollBar()
        scroll_at_end = scrollbar.value() == scrollbar.maximum()
        if level >= logging.ERROR:
            fmt = self._err_fmt
        elif level >= logging.WARNING:
            fmt = self._warn_fmt
        elif level >= logging.INFO:
            fmt = self._info_fmt
        else:
            fmt = self._std_fmt
        cursor = self.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(s, fmt)
        if end:
            cursor.insertText(end)
        if scroll_at_end:
            scrollbar.setValue(scrollbar.maximum())


class ConsoleHandler(QtCore.QObject, logging.Handler):

    _signal = QtCore.pyqtSignal(object)

    def __init__(self, console):
        super().__init__()
        self._console = console
        self._signal.connect(self._emit)

    def emit(self, record):
        self._signal.emit(record)

    def _emit(self, record):
        self._console.log(record.levelno, self.formatter.format(record))


class Tester(QtWidgets.QMainWindow):

    _test_done = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ctrl = Controller()
        self._ctrl.requested.connect(self._on_cmd)
        self.resize(640, 480)
        self.setMinimumSize(QtCore.QSize(640, 480))
        self.setWindowTitle('OFT EVA Tester')
        widget = QtWidgets.QWidget()
        self.setCentralWidget(widget)
        self._vbox = QtWidgets.QVBoxLayout()
        widget.setLayout(self._vbox)
        gbox = QtWidgets.QGroupBox('Serial port')
        hbox = QtWidgets.QHBoxLayout()
        gbox.setLayout(hbox)
        self._vbox.addWidget(gbox)
        self._port = QtWidgets.QComboBox()
        hbox.addWidget(self._port)
        self._scan = QtWidgets.QPushButton('Scan')
        self._scan.clicked.connect(self.on_scan)
        hbox.addWidget(self._scan)
        self._console = Console()
        self.setup_log()
        self._vbox.addWidget(self._console, 1)
        hbox = QtWidgets.QHBoxLayout()
        self._vbox.addLayout(hbox)
        self._start = QtWidgets.QPushButton('Start test')
        self._start.clicked.connect(self.on_start)
        self._tests_menu = QtWidgets.QMenu()
        for test_name, test_fn in TEST_LIST:
            action = self._tests_menu.addAction(test_name)
            action.triggered.connect(functools.partial(self._start_test, test_name, test_fn))
        self._stop = QtWidgets.QPushButton('Stop test')
        self._stop.clicked.connect(self.on_stop)
        self._stop.setEnabled(False)
        hbox.addWidget(self._start)
        hbox.addWidget(self._stop)
        self._test_done.connect(self._on_test_done)
        self._test = None
        self._quit = False
        self.on_scan()

    def closeEvent(self, event):
        if self._test is None:
            return
        self._quit = True
        self.on_stop()
        event.ignore()

    def on_scan(self):
        self._port.clear()
        serial_ports = sorted(x[0] for x in comports())
        self._port.insertItems(0, serial_ports)

    def on_start(self):
        self._tests_menu.exec_(QtGui.QCursor.pos())

    def on_stop(self):
        self._log.info('stopping test')
        self._stop.setEnabled(False)
        self._ctrl.stop()

    def _on_cmd(self, cmd, args):
        if cmd == 'prompt':
            dlg = QtWidgets.QInputDialog(self)
            dlg.setInputMode(dlg.TextInput)
            dlg.setOption(dlg.UsePlainTextEditForTextInput)
            dlg.setLabelText(args[0])
            dlg.setWindowTitle(self.windowTitle())
            for child in dlg.children():
                if isinstance(child, QtWidgets.QPlainTextEdit):
                    child.setTabChangesFocus(True)
                    break
            if dlg.exec_() == dlg.Accepted:
                result = dlg.textValue()
            else:
                result = None
            self._log.info('%s %s', args[0], result)
        elif cmd == 'information':
            QtWidgets.QMessageBox.information(self, self.windowTitle(), *args)
            result = None
            self._log.info('%s', args[0])
        elif cmd == 'question':
            result = QtWidgets.QMessageBox.question(self, self.windowTitle(), *args)
            result = result == QtWidgets.QMessageBox.Yes
            self._log.info('%s %s', args[0], result)
        else:
            raise ValueError(cmd)
        self._ctrl.reply(result)

    def _on_test_done(self):
        self._log.info('test stopped')
        self._stop.setEnabled(False)
        self._start.setEnabled(True)
        self._test.join()
        self._test = None
        self._ctrl.reset()
        if self._quit:
            self.close()

    def _start_test(self, test_name, test_fn):
        self._log.info('starting test: %s', test_name)
        self._test = threading.Thread(target=self._run_test, args=(test_fn,))
        self._test.start()
        self._stop.setEnabled(True)
        self._start.setEnabled(False)

    def _run_test(self, test_fn):
        try:
            port = setup_serial(self._log, dev=self._port.currentText())
            try:
                cxn = OftEvaConnection(port)
                test_fn(self._ctrl, self._log, cxn)
            except EOFError:
                pass
            finally:
                port.close()
        except:
            self._log.exception('got exception during test')
        finally:
            self._test_done.emit()

    def setup_log(self):
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        log = logging.getLogger(__name__)
        log.setLevel(logging.DEBUG)
        handler = ConsoleHandler(self._console)
        handler.setFormatter(formatter)
        log.addHandler(handler)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        log.addHandler(handler)
        logfile_num = 1
        logfile_match = '%s_([0-9]+).log' % __name__
        for existing_logfile in Path('.').iterdir():
            m = re.fullmatch(logfile_match, existing_logfile.name)
            if m is not None:
                logfile_num = max(int(m.group(1)) + 1, logfile_num)
        logfile = '%s_%u.log' % (__name__, logfile_num)
        log.info('logging to %s', logfile)
        handler = logging.FileHandler(logfile)
        handler.setFormatter(formatter)
        log.addHandler(handler)
        self._log = log

def main():
    QtCore.pyqtRemoveInputHook()
    app = QtWidgets.QApplication([])
    win = Tester()
    win.show()
    app.exec_()


if __name__ == '__main__':
    main()
