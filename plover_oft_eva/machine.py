"""
Support for the OFT EVA keyboard: http://www.oft-coop.com/EVA/.


PROTOCOL
========

stroke packet + 9 (?) commands:

0x01: set keyboard settings
    command: 251 bytes, 0x01 + settings
    reply: 0x06

0x02: get keyboard settings
    command: 0x02
    reply: 251 bytes, 0x02 + settings

0x03: led settings
    command: 0x03 + LED RGB channel [0x00-0x05] + intensity [0x00-0x64] / [0-100%]
    reply: 0x06
    - LED 1 BGR: 03:00:xx 03:01:xx 03:02:xx
    - LED 2 BGR: 03:03:xx 03:04:xx 03:05:xx

0x17: trigger a beep
    command: 17:07:d0:00:50:00:96
    reply: 0x06

0x18: ???
    command: 18:0c:1c:00:00:00:01
    reply: 0x06

0x19: get keyboard serial
    command: 0x19
    reply: 16 bytes, 0x19 + serial
    (e.g.: 19:09:19:30:c5:44:37:46:47:39:2e:31:20:ff:16:11
    => serial is 09-1930-c544-3746-4739-2e31-20ff-1611)

0x1a: toggle strokes processing
    command: 1a:01 (enable), 1a:00 (disable)
    reply: 0x06

0x1c: get keyboard (firmware?) version
    command: 0x1c
    reply: 0x1c + version + 0d:0a
    (e.g.: 1c:31:32:31:2e:35:39:31:0d:0a => version is 121.591)

0x1d: ???
    command: 1d
    reply: 1d:01

keyboard settings:

250      ╭─ key sensitivity: 0xa0-0xaf (high to low)
bytes    │   ╭─ key enabled/disabled: 0x21/0x20
         ╵   ╵
00  a3  -E
01  a3  -O
02  a6
03  a6
04  a6
05  a3  #1
06  a6
07  a6
08  a3  *3
09  a3  -c
0a  a3  -t
0b  a3  -p
0c  a3  -i
0d  a3  -a
0e  a6
0f  a6
10  a3  *4
11  a3  -s
12  a3  -h
13  a3  -r
14  a3  -e
15  a3  -o
16  a6
17  a6
18  4f
…
2f  4f
30  21      -E
31  21      -O
32  52
33  52
34  52
35  21      #2
36  52
37  52
38  21      *3
39  21      -c
3a  21      -t
3b  21      -p
3c  21      -i
3d  21      -a
3e  52
3f  52
40  21      *4
41  21      -s
42  21      -h
43  21      -r
44  21      -e
45  21      -o
46  52
47  52
48  14
…
5f  14
60  2f
…
77  2f
78  bb
79  19
7a  0a
7b  a3  #2
7c  a5
7d  a5
7e  a6
7f  a3  I-
80  a3  A-
81  a6
82  a6
83  a3  X1-
84  a3  S1-
85  a3  P-
86  a3  T-
87  a3  V-
88  a3  *1
89  a6
8a  a6
8b  a3  X2-
8c  a3  S2-
8d  a3  C-
8e  a3  H-
8f  a3  R-
90  a3  *2
91  a6
92  a6
93  4f
…
aa  4f
ab  21      #1
ac  50
ad  50
ae  50
af  21      I-
b0  21      A-
b1  50
b2  52
b3  21      X1-
b4  21      S1-
b5  21      P-
b6  21      T-
b7  21      V-
b8  21      *1
b9  52
ba  52
bb  21      X2-
bc  21      S2-
bd  21      C-
be  21      H-
bf  21      R-
c0  21      *2
c1  52
c2  52
c3  14
c4  64
c5  9b
c6  01
c7  14
c8  14
c9  00
ca  14
…
da  14
db  2e
dc  2f
…
f2  2f
f3  bb
f4  19
f5  0a
f6  00
f7  00
f8  00
f9  64

stroke packet: 1 byte per key + 0xa0, 30 possible keys
keycode: [0x32, 0x5f] [46 possibilities, only 30 used]
mapping:
    0x32      => #1
    0x33-0x35 => unused
    0x36      => -O
    0x37      => -E
    0x38-0x39 => unused
    0x3a      => -a
    0x3b      => -i
    0x3c      => -p
    0x3d      => -t
    0x3e      => -c
    0x3f      => *3
    0x40-0x41 => unused
    0x42      => -o
    0x43      => -e
    0x44      => -r
    0x45      => -h
    0x46      => -s
    0x47      => *4
    0x48-0x49 => unused
    0x4a      => A-
    0x4b      => I-
    0x4c-0x4e => unused
    0x4f      => #2
    0x50-0x51 => unused
    0x52      => *1
    0x53      => V-
    0x54      => T-
    0x55      => P-
    0x56      => S1-
    0x57      => X1-
    0x58-0x59 => unused
    0x5a      => *2
    0x5b      => R-
    0x5c      => H-
    0x5d      => C-
    0x5e      => S2-
    0x5f      => X2-

application handshake sequence:
  - get serial
  - get version
  - get settings
  - disable strokes
  - switch off LED 2
  - progressively switch LED 1 from orange to green
  - send mystery command: 17:07:d0:00:50:00:96
  - switch off LED 1
  - enable strokes
  - switch LED 2 to green

"""

from collections import namedtuple
import ast

from plover import log
from plover.machine.base import SerialStenotypeBase
from plover.misc import boolean


class KeySettings(namedtuple('KeySettings', 'enabled sensitivity')):

    def __new__(cls, enabled=True, sensitivity=4):
        return super().__new__(cls, enabled, sensitivity)

    def __repr__(self):
        return repr(self._asdict())

    @classmethod
    def decode(cls, enabled, sensitivity):
        if enabled == 0x20:
            enabled = False
        elif enabled == 0x21:
            enabled = True
        else:
            raise ValueError('invalid key enabled value: %#x' % enabled)
        if sensitivity < 0xa0 or sensitivity > 0xaf:
            raise ValueError('invalid key sensitivity value: %#x' % sensitivity)
        sensitivity = 0xaf - sensitivity
        return cls.__new__(cls, enabled=enabled, sensitivity=sensitivity)

    def encode(self):
        assert 0 <= self.sensitivity <= 15
        return (0x21 if self.enabled else 0x20, 0xaf - self.sensitivity)

KeySettings.DEFAULT = KeySettings()


_DECODE_KEY = {
    # First row: number bar.
    0x32: '#1',
    0x4f: '#2',
    # Second row.
    0x57: 'X1-',
    0x56: 'S1-',
    0x55: 'P-',
    0x54: 'T-',
    0x53: 'V-',
    0x52: '*1',
    0x3f: '*3',
    0x3e: '-c',
    0x3d: '-t',
    0x3c: '-p',
    0x3b: '-i',
    0x3a: '-a',
    # Third row.
    0x5f: 'X2-',
    0x5e: 'S2-',
    0x5d: 'C-',
    0x5c: 'H-',
    0x5b: 'R-',
    0x5a: '*2',
    0x47: '*4',
    0x46: '-s',
    0x45: '-h',
    0x44: '-r',
    0x43: '-e',
    0x42: '-o',
    # Last row: thumb keys.
    0x4b: 'I-',
    0x4a: 'A-',
    0x37: '-E',
    0x36: '-O',
}

_DECODE_SETTINGS = {
    'keys': (KeySettings.decode, {
        # First row.
        '#1' : (0xab, 0x05),
        '#2' : (0x35, 0x7b),
        # Second row.
        'X1-': (0xb3, 0x83),
        'S1-': (0xb4, 0x84),
        'P-' : (0xb5, 0x85),
        'T-' : (0xb6, 0x86),
        'V-' : (0xb7, 0x87),
        '*1' : (0xb8, 0x88),
        '*3' : (0x38, 0x08),
        '-c' : (0x39, 0x09),
        '-t' : (0x3a, 0x0a),
        '-p' : (0x3b, 0x0b),
        '-i' : (0x3c, 0x0c),
        '-a' : (0x3d, 0x0d),
        # Third row.
        'X2-': (0xbb, 0x8b),
        'S2-': (0xbc, 0x8c),
        'C-' : (0xbd, 0x8d),
        'H-' : (0xbe, 0x8e),
        'R-' : (0xbf, 0x8f),
        '*2' : (0xc0, 0x90),
        '*4' : (0x40, 0x10),
        '-s' : (0x41, 0x11),
        '-h' : (0x42, 0x12),
        '-r' : (0x43, 0x13),
        '-e' : (0x44, 0x14),
        '-o' : (0x45, 0x15),
        # Last row.
        'I-' : (0xaf, 0x7f),
        'A-' : (0xb0, 0x80),
        '-E' : (0x30, 0x00),
        '-O' : (0x31, 0x01),
    }),
}


class ProtocolViolationException(Exception):
    """Something has happened that doesn't follow the protocol."""

class ReadTimeout(Exception):
    """Timeout during a read operation."""



class OftEvaConnection:

    def __init__(self, port):
        self._port = port

    def _read_cr_packet(self):
        packet = b''
        while True:
            raw = self._port.read(1)
            if not raw:
                # Timeout.
                if packet:
                    # 'Short' packet.
                    log.error('discarding incomplete packet: %s', packet.hex(':'))
                raise ReadTimeout()
            if raw == b'\n':
                # Full packet.
                return packet
            # Packet is not yet finished.
            packet += raw

    @staticmethod
    def _decode_settings(packet):
        settings = {}
        for section, (decode_fn, key_list) in _DECODE_SETTINGS.items():
            settings[section] = section = {}
            for key, field_list in key_list.items():
                try:
                    value = decode_fn(*(packet[i] for i in field_list))
                except ValueError as e:
                    raise ProtocolViolationException(e) from e
                section[key] = value
        return settings

    @staticmethod
    def _encode_settings(packet, settings):
        for section, (decode_fn, key_list) in _DECODE_SETTINGS.items():
            section = settings.get(section)
            if section is None:
                continue
            for key, field_list in key_list.items():
                value = section.get(key)
                if value is None:
                    continue
                for i, b in zip(field_list, value.encode()):
                    packet[i] = b

    @staticmethod
    def _decode_stroke(packet):
        stroke = []
        for b in packet:
            key = _DECODE_KEY.get(b)
            if key is None:
                log.error('unknown key: 0x%02x', b)
                continue
            stroke.append(key)
        return stroke

    def send_receive(self, message, expected_reply_len, expected_reply_ack):
        sent = self._port.write(message)
        assert sent == len(message)
        if expected_reply_len:
            reply = self._port.read(expected_reply_len)
            if len(reply) != expected_reply_len or \
               not reply.startswith(expected_reply_ack):
                raise ProtocolViolationException(
                    'sent %s [%u] and expected %s%s [%u] back but got: %r [%u]' % (
                        message.hex(':'), len(message),
                        expected_reply_ack.hex(':'), ':...' if
                        expected_reply_len > len(expected_reply_ack) else '',
                        expected_reply_len, reply.hex(':'), len(reply),
                    ))
        else:
            reply = self._read_cr_packet()
            if not reply.startswith(expected_reply_ack):
                raise ProtocolViolationException(
                    'sent %s [%u] and expected %s..0a back but got: %r [%u]' % (
                        message.hex(':'), len(message),
                        expected_reply_ack.hex(':'),
                        reply.hex(':'), len(reply),
                ))
        return reply

    def reset_input_buffer(self):
        self._port.reset_input_buffer()

    def get_settings(self):
        packet = self.send_receive(b'\x02', 251, b'\x02')[1:]
        return self._decode_settings(packet)

    def update_settings(self, update):
        # Fetch current settings.
        packet = bytearray(self.send_receive(b'\x02', 251, b'\x02')[1:])
        # Decode them to detect any unsupported protocol change.
        self._decode_settings(packet)
        # Update.
        self._encode_settings(packet, update)
        # Commit.
        packet.insert(0, 0x01)
        self.send_receive(packet, 1, b'\x06')

    def get_serial(self):
        return self.send_receive(b'\x19', 16, b'\x19')[1:].hex()

    def get_version(self):
        return self.send_receive(b'\x1c', 0, b'\x1c')[1:].decode('ascii').rstrip('\r')

    def set_led(self, num, rgb):
        assert 0 <= num <= 1
        assert len(rgb) == 3
        rgb = bytes(rgb)
        for n, v in enumerate(reversed(rgb)):
            self.send_receive(bytes((0x03, num * 3 + n, round(v / 2.55))), 1, b'\x06')

    def trigger_beep(self):
        self.send_receive(b'\x17\x07\xd0\x00\x50\x00\x96', 1, b'\x06')

    def toggle_strokes(self, enabled):
        self.send_receive(b'\x1a' + bytes((int(bool(enabled)),)), 1, b'\x06')

    def read_stroke(self):
        packet = self._read_cr_packet()
        return self._decode_stroke(packet)

    def opening_handshake(self):
        self.reset_input_buffer()
        self.toggle_strokes(False)
        log.info('serial: %s' % self.get_serial())
        log.info('version: %s' % self.get_version())
        # First LED off, second green.
        self.set_led(0, (0, 0, 0))
        self.set_led(1, (0, 128, 0))
        self.toggle_strokes(True)

    def closing_handshake(self):
        self.reset_input_buffer()
        self.toggle_strokes(False)
        # Clear LEDs.
        self.set_led(0, (0, 0, 0))
        self.set_led(1, (0, 0, 0))


class OftEvaMachine(SerialStenotypeBase):

    # In Eva application: NnSPCTHVRIA*EOcsthprieao$
    # Nn => additional two keys on the left
    # $ => number key

    KEYS_LAYOUT = '''
      #1  #1  #1 #1 #1 #1   #2 #2 #2 #2 #2 #2
      X1- S1- P- T- V- *1   *3 -c -t -p -i -a
      X2- S2- C- H- R- *2   *4 -s -h -r -e -o
                    I- A-   -E -O
    '''

    SERIAL_PARAMS = dict(SerialStenotypeBase.SERIAL_PARAMS)
    SERIAL_PARAMS.update(timeout=0.25)

    def __init__(self, options):
        super().__init__(options['serial'])
        self._options = options

    def run(self):
        cxn = OftEvaConnection(self.serial_port)
        try:
            cxn.opening_handshake()
            if self._options['override_keyboard_settings']:
                cxn.update_settings(self._options)
            if self._options['beep_on_connection']:
                cxn.trigger_beep()
        except:
            log.error('handshake failed', exc_info=True)
            self._close_port()
            self._error()
            return
        self._ready()
        while not self.finished.isSet():
            try:
                stroke = cxn.read_stroke()
            except ReadTimeout:
                continue
            steno_keys = self.keymap.keys_to_actions(stroke)
            if steno_keys:
                self._notify(steno_keys)
        cxn.closing_handshake()

    @classmethod
    def _keys_config_converter(cls, v):
        if isinstance(v, dict):
            return v
        errors = []
        valid_keys = set(cls.KEYS_LAYOUT.split())
        raw_settings = dict(ast.literal_eval(v))
        invalid_keys = set(raw_settings.keys()) - valid_keys
        if invalid_keys:
            errors.append("invalid keys: %s" % ', '.join(map(str, sorted(invalid_keys))))
        settings = {}
        for k in valid_keys:
            v = raw_settings.get(k, KeySettings.DEFAULT)
            if v is not KeySettings.DEFAULT:
                try:
                    v = KeySettings(**dict(v))
                except ValueError as e:
                    errors.append('invalid key settings for %s: %s' % (k, str(e)))
            settings[k] = v
        if errors:
            raise ValueError('\n'.join(errors))
        return settings

    @classmethod
    def _serial_config_converter(cls, v):
        if isinstance(v, dict):
            return v
        serial_options = super().get_option_info()
        serial_params = dict(ast.literal_eval(v))
        return {
            opt: serial_params.get(opt, default)
            for opt, (default, converter) in serial_options.items()
        }

    @classmethod
    def get_option_info(cls):
        keys_defaults = {
            k: KeySettings.DEFAULT._asdict()
            for k in cls.KEYS_LAYOUT.split()
        }
        serial_defaults = {
            opt: default
            for opt, (default, converter)
            in super().get_option_info().items()
        }
        options = {
            'override_keyboard_settings': (False, boolean),
            'beep_on_connection': (True, boolean),
            'keys': (keys_defaults, cls._keys_config_converter),
            'serial': (serial_defaults, cls._serial_config_converter),
        }
        return options
