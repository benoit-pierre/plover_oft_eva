from copy import copy, deepcopy

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import Qt

from serial.tools.list_ports import comports

from plover.gui_qt.machine_options import SerialOption

from plover_oft_eva.machine import OftEvaMachine


class OptionDialog(QtWidgets.QDialog):

    def __init__(self, option, value, parent=None):
        super().__init__(parent)
        self._option = option
        self._old_value = self._new_value = value
        vbox = QtWidgets.QVBoxLayout()
        bbox = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok |
                                          QtWidgets.QDialogButtonBox.Cancel)
        vbox.addWidget(option)
        vbox.addWidget(bbox)
        self.setLayout(vbox)
        option.setValue(value)
        option.valueChanged.connect(self._on_value_changed)
        bbox.accepted.connect(self.accept)
        bbox.rejected.connect(self.reject)

    def _on_value_changed(self, value):
        self._new_value = value

    @property
    def value(self):
        if self.result() == self.Accepted:
            return self._new_value
        return self._old_value


class KeysSettingsOption(QtWidgets.QTableWidget):

    valueChanged = QtCore.pyqtSignal(object)

    class _Delegate(QtWidgets.QItemDelegate):

        def createEditor(self, parent, option, index):
            col = index.column()
            if col == 1:
                widget = QtWidgets.QSpinBox(parent)
                widget.setMinimum(0)
                widget.setMaximum(15)
                return widget
            return super().createEditor(parent, option, index)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = {}
        self._keys = tuple(dict.fromkeys(OftEvaMachine.KEYS_LAYOUT.split()).keys())
        self.setItemDelegate(self._Delegate())
        self.setColumnCount(2)
        self.setRowCount(len(self._keys))
        self.setVerticalHeaderLabels(self._keys)
        self.setHorizontalHeaderLabels(('Enabled', 'Sensitivity'))
        self.itemChanged.connect(self._on_item_changed)

    def setValue(self, value):
        self._value = copy(value)
        for row, key in enumerate(self._keys):
            settings = value[key]
            item = QtWidgets.QTableWidgetItem()
            item.setCheckState(settings.enabled)
            item.setCheckState(Qt.Checked if settings.enabled else Qt.Unchecked)
            self.setItem(row, 0, item)
            item = QtWidgets.QTableWidgetItem()
            item.setData(Qt.DisplayRole, settings.sensitivity)
            self.setItem(row, 1, item)

    def _on_item_changed(self, item):
        key = self._keys[item.row()]
        settings = self._value[key]
        col = item.column()
        if col == 0:
            field = 'enabled'
            value = item.checkState() == Qt.Checked
        elif col == 1:
            field = 'sensitivity'
            value = item.data(Qt.DisplayRole)
        else:
            raise ValueError(item)
        settings = settings._replace(**{field: value})
        self._value[key] = settings
        self.valueChanged.emit(self._value)


class OftEvaOption(QtWidgets.QWidget):

    valueChanged = QtCore.pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self._value = {}
        vbox = QtWidgets.QVBoxLayout()
        self.setLayout(vbox)
        serial_frame = QtWidgets.QGroupBox('Serial:')
        vbox.addWidget(serial_frame)
        serial_layout = QtWidgets.QHBoxLayout()
        serial_frame.setLayout(serial_layout)
        serial_port = QtWidgets.QComboBox()
        serial_layout.addWidget(serial_port, 1)
        serial_port.setEditable(True)
        serial_scan = QtWidgets.QPushButton('Scan')
        serial_layout.addWidget(serial_scan)
        serial_advanced = QtWidgets.QPushButton('Advanced')
        serial_layout.addWidget(serial_advanced)
        keys_frame = QtWidgets.QGroupBox('Keys:')
        vbox.addWidget(keys_frame)
        keys_layout = QtWidgets.QHBoxLayout()
        keys_frame.setLayout(keys_layout)
        override_keyboard_settings = QtWidgets.QCheckBox('Override keyboard settings')
        keys_layout.addWidget(override_keyboard_settings, 1)
        keys_configure = QtWidgets.QPushButton('Configure')
        keys_configure.setEnabled(False)
        keys_layout.addWidget(keys_configure)
        sound_frame = QtWidgets.QGroupBox('Sound:')
        vbox.addWidget(sound_frame)
        sound_layout = QtWidgets.QFormLayout()
        sound_frame.setLayout(sound_layout)
        beep_on_connection = QtWidgets.QCheckBox('Beep on connection')
        sound_layout.addRow(beep_on_connection)
        self._keys_configure = keys_configure
        self._serial_port = serial_port
        self._override_keyboard_settings = override_keyboard_settings
        self._beep_on_connection = beep_on_connection
        self._on_serial_scan()
        serial_port.editTextChanged['QString'].connect(self._on_serial_port_changed)
        serial_scan.clicked.connect(self._on_serial_scan)
        serial_advanced.clicked.connect(self._on_serial_advanced)
        keys_configure.clicked.connect(self._on_keys_configure)
        override_keyboard_settings.stateChanged.connect(self._on_override_keyboard_settings_changed)
        override_keyboard_settings.stateChanged.connect(keys_configure.setEnabled)
        beep_on_connection.stateChanged.connect(self._on_beep_on_connection_changed)

    def setValue(self, value):
        self._value = deepcopy(value)
        port = value['serial']['port']
        if port is not None and port != 'None':
            self._select_serial_port(port)
        override = value['override_keyboard_settings']
        self._override_keyboard_settings.setCheckState(Qt.Checked if override else Qt.Unchecked)
        beep = value['beep_on_connection']
        self._beep_on_connection.setCheckState(Qt.Checked if beep else Qt.Unchecked)

    def _update(self, section, field, value):
        if section is None:
            self._value[field] = value
        else:
            self._value[section][field] = value
        self.valueChanged.emit(self._value)

    def _select_serial_port(self, port):
        if port is None or port == 'None':
            self._serial_port.setCurrentIndex(0)
        else:
            self._serial_port.setCurrentText(port)

    def _on_serial_scan(self):
        port = self._serial_port.currentText()
        self._serial_port.clear()
        self._serial_port.addItems(sorted(x[0] for x in comports()))
        self._select_serial_port(port)

    def _on_serial_port_changed(self, value):
        self._update('serial', 'port', value)

    def _on_serial_advanced(self):
        dialog = OptionDialog(SerialOption(), self._value['serial'], self)
        if dialog.exec_() != dialog.Accepted:
            return
        serial_params = dialog.value
        self._select_serial_port(serial_params['port'])
        self._update(None, 'serial', serial_params)

    def _on_override_keyboard_settings_changed(self, state):
        self._update(None, 'override_keyboard_settings', bool(state))

    def _on_beep_on_connection_changed(self, state):
        self._update(None, 'beep_on_connection', bool(state))

    def _on_keys_configure(self):
        dialog = OptionDialog(KeysSettingsOption(), self._value['keys'], self)
        if dialog.exec_() != dialog.Accepted:
            return
        self._update(None, 'keys', dialog.value)
