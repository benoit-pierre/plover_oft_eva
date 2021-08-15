#!/usr/bin/env python

from dataclasses import dataclass
import binascii
import json
import sys


@dataclass
class Packet:
    timestamp: float
    delta: float
    kind: str
    data: bytes
    comment: str


def merge_packets(packet_list):
    packet = None
    for new_packet in packet_list:
        if (packet is None or
            new_packet.kind != packet.kind or
            new_packet.delta > 0.015):
            if packet is not None:
                yield packet
            packet = new_packet
        else:
            if new_packet.comment:
                if packet.comment:
                    packet.comment += '\n'
                packet.comment += new_packet.comment
            packet.data += new_packet.data
    if packet is not None:
        yield packet


def main():
    with open(sys.argv[1], 'rb') as fp:
        capture = json.load(fp)
    # Filter out interesting data.
    packet_list = []
    prev_timestamp = 0
    for packet in capture:
        layers = packet['_source']['layers']
        frame = layers['frame']
        usb = layers['usb']
        timestamp = float(frame['frame.time_relative'])
        delta = timestamp - prev_timestamp
        comment = layers.get('pkt_comment')
        if comment is not None:
            comment = comment['frame.comment']
        data = layers.get('usb.capdata')
        if data is None:
            continue
        src = usb['usb.src']
        dst = usb['usb.dst']
        if dst == 'host':
            kind = '%s => host' % src
        elif src == 'host':
            kind = 'host => %s' % dst
        else:
            raise ValueError(src, dst)
        data = binascii.unhexlify(data.replace(':', ''))
        packet = Packet(timestamp, delta, kind, data, comment or '')
        packet_list.append(packet)
        prev_timestamp = timestamp
    # Regurgitate, merging time adjacent packets.
    for packet in merge_packets(packet_list):
        print('% 8.3f [% +7.3f]  %s  %3u  %s  %s  %r' % (
            packet.timestamp, packet.delta,
            packet.kind,
            len(packet.data),
            packet.data.hex(':'),
            ':'.join("{0:08b}".format(b) for b in packet.data),
            packet.data,
        ))
        if packet.comment:
            print('', '^' * 8, packet.comment)


if __name__ == '__main__':
    main()
