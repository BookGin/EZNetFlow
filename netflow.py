#!/usr/bin/env python3
from struct import unpack
import datetime

class NetFlowPacket:
    SIZE_OF_HEADER = 24
    SIZE_OF_FLOW = 48

    def __init__(self, packet):
        self.header = self._parseHeader(packet[: NetFlowPacket.SIZE_OF_HEADER])
        self.flows = self._parseFlows(packet[NetFlowPacket.SIZE_OF_HEADER: ], self.header['count'])

    def _parseHeader(self, raw_data):
        attributes = ['version', 'count', 'sysuptime_msec', 'utimestamp', 'ntimstamp', 'flow_seq', 'engine_type', 'engine_id', 'sample_mode']
        values = unpack('!HHIiiIBBH', raw_data)
        return dict(zip(attributes, values))

    def _parseFlows(self, flow_packets, count):
        return [Flow(flow_packets[i * NetFlowPacket.SIZE_OF_FLOW: (i+1) * NetFlowPacket.SIZE_OF_FLOW]) for i in range(count)]

class Flow:
    def __init__(self, raw_flow_data):
        self._attributes = self._parse(raw_flow_data)

    def __getattr__(self, attr):
        return self._attributes[attr]

    def _parse(self, raw_data):
        attributes = ['src_ip', 'dst_ip', 'next_hop', 'input_int', 'output_int', 'packet_count', 'packet_octet', 'start_time', 'end_time', 'src_port', 'dst_port', 'tcp_flags', 'protocol', 'ip_tos', 'src_as', 'dst_as', 'src_mask', 'dst_mask']
        values = unpack('!IIIHHIIIIHHxBBBHHBBxx', raw_data)
        dic = dict(zip(attributes, values))

        # Make raw integer IP become IP string
        for raw_ip in ['src_ip', 'dst_ip', 'next_hop']:
            dic[raw_ip] = self._toIPString(dic[raw_ip])
        return dic

    def _toIPString(self, raw_ip):
        hex_str = '{:08x}'.format(raw_ip)
        li = [str(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2)]
        return '.'.join(li)

class HostStatistic:
    def __init__(self):
        self.tx_count, self.tx_octet = 0, 0
        self.rx_count, self.rx_octet = 0, 0
        self.last_seen = 0

    def addTxTraffic(self, count, octet, last_seen):
        self.tx_count += count
        self.tx_octet += octet
        self.last_seen = last_seen

    def addRxTraffic(self, count, octet, last_seen):
        self.rx_count += count
        self.rx_octet += octet
        self.last_seen = last_seen

class Hosts:
    def __init__(self):
        self.ips = {}

    def accountTraffic(self, src_ip, dst_ip, count, octet, last_seen):
        if src_ip not in self.ips:
            self.ips[src_ip] = HostStatistic()
        if dst_ip not in self.ips:
            self.ips[dst_ip] = HostStatistic()

        self.ips[src_ip].addTxTraffic(count, octet, last_seen)
        self.ips[dst_ip].addRxTraffic(count, octet, last_seen)

packet = open('./test', 'rb').read() #[42:]
nf = NetFlowPacket(packet)

# Simple traffic accounting
hosts = Hosts()
for flow in nf.flows:
    hosts.accountTraffic(flow.src_ip, flow.dst_ip, flow.packet_count, flow.packet_octet, nf.header['utimestamp'])

for ip, flow in hosts.ips.items():
    tx_percent = flow.tx_octet / (flow.tx_octet + flow.rx_octet) * 100
    print('{:<15} total_bytes:{:<10} Tx {:<5}% Rx {:<5}%, last seen:{}'.format(
        ip, flow.tx_octet + flow.rx_octet, tx_percent, 100 - tx_percent, datetime.datetime.fromtimestamp(flow.last_seen).strftime('%Y-%m-%d %H:%M:%S')
    ))
