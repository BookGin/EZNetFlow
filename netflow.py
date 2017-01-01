#!/usr/bin/env python3
import socket
import struct
from datetime import datetime

class NetFlowPacket:
    SIZE_OF_HEADER = 24
    SIZE_OF_FLOW = 48

    def __init__(self, packet):
        self.header = self._parseHeader(packet[: NetFlowPacket.SIZE_OF_HEADER])
        self.flows = self._parseFlows(packet[NetFlowPacket.SIZE_OF_HEADER: ], self.header['count'])

        if len(packet[NetFlowPacket.SIZE_OF_HEADER + self.header['count'] * NetFlowPacket.SIZE_OF_FLOW: ]) != 0:
            print('\x1b[0;30;43m', end="")
            print("warning: > 2 netflow data in one udp packet", end='')
            print('\x1b[0m')

    def _parseHeader(self, raw_data):
        attributes = ['version', 'count', 'sysuptime_msec', 'utimestamp', 'ntimstamp', 'flow_seq', 'engine_type', 'engine_id', 'sample_mode']
        values = struct.unpack('!HHIiiIBBH', raw_data)
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
        values = struct.unpack('!IIIHHIIIIHHxBBBHHBBxx', raw_data)
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

    def analyzeTraffic(self, src_port, dst_ip, dst_port, protocol):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        print("layer 4 protocol is ", end="")
        if protocol in protocols:
            print(protocols[protocol])
        else:
            print("unknown")

        ports = {
            20: 'ftp data', 21: 'ftp ctl', 22: 'ssh', 23: 'telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            69: 'tftp', 80: 'http', 110: 'POP3', 123: 'NTP', 389: 'LDAP', 443: 'https', 1194: 'OpenVPN', 8080: 'http_alt'
        }
        if dst_port in ports:
            print("des: layer 5 protocol is", ports[dst_port])
        if src_port in ports:
            print("src: layer 5 protocol is ", ports[src_port])



# Simple traffic accounting
LISTEN_IP = '127.0.0.1'
LISTEN_PORT = 2055
UDP_RECV_BUFFER_SIZE = 1024

udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udpsocket.bind((LISTEN_IP, LISTEN_PORT))

hosts = Hosts()
while True:
    packet, (ip, port) = udpsocket.recvfrom(UDP_RECV_BUFFER_SIZE)
    print("recv from {}:{}".format(ip, port))

    try:
        nf = NetFlowPacket(packet)
    except struct.error:
        print('\x1b[0;30;41m' + 'Recv corrupt packet, cannot unpack it' + '\x1b[0m')
        continue

    for flow in nf.flows:
        hosts.accountTraffic(flow.src_ip, flow.dst_ip, flow.packet_count, flow.packet_octet, nf.header['utimestamp'])
        hosts.analyzeTraffic(flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol)

    for ip, flow in hosts.ips.items():
        tx_percent = flow.tx_octet / (flow.tx_octet + flow.rx_octet) * 100
        print('{:<15} total transfer bytes:{:<10d} Tx {:<2.2f}% Rx {:<2.2f}%, last seen:{}'.format(
        ip, flow.tx_octet + flow.rx_octet, tx_percent, 100 - tx_percent, datetime.fromtimestamp(flow.last_seen).strftime('%Y-%m-%d %H:%M:%S')
        ))
