import binascii
import socket
import struct
import threading
from time import *
import sys

protocol_count = {
    'ARP': 0,
    'IPv4': 0,
    'IPv6': 0,
    'ICMP': 0,
    'ICMPv6': 0,
    'TCP': 0,
    'UDP': 0,
}


def check_time():
    startTime = time()
    startCount = protocol_count['ICMP']
    print('iniciou o checktime')
    while True:
        if time() - startTime >= 10:
            print('entrou no if que passou 3 segundos')
            startTime = time()
            startCount = protocol_count["ICMP"]
            print(startTime, startCount)
            print(protocol_count["ICMP"])
        else:
            if protocol_count["ICMP"] - startCount > 100:
                print("ICMP Flooding!")
                sys.exit()


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth_proto, data = ethernet_frame(raw_data)

        eHeader = raw_data[0:14]
        eth_hdr = struct.unpack("!6s6s2s", eHeader)

        eth_type = binascii.hexlify(eth_hdr[2]).decode('utf-8')

        if eth_type == '0806':
            # print("\nARP Packet:")
            protocol_count['ARP'] += 1

        # Ethernet Type 34525: IPv6
        elif eth_type == '86dd':
            ipv6_data = ipv6_packet(data)
            protocol_count['IPv6'] += 1

            if ipv6_data['next_header'] == 58:
                protocol_count['ICMPv6'] += 1

        # print("\nProtocol Count:")
        for protocol, count in protocol_count.items():
            print(f"{protocol}: {count}")

        if eth_proto == 8:
            ipv4_data = ipv4_packet(data)
            protocol_count['IPv4'] += 1

            if ipv4_data['protocol'] == 1:
                protocol_count['ICMP'] += 1

            elif ipv4_data['protocol'] == 6:
                protocol_count['TCP'] += 1

            elif ipv4_data['protocol'] == 17:
                protocol_count['UDP'] += 1


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])

    return socket.htons(proto), data[14:]


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src_ip, dest_ip = struct.unpack(
        '! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': protocol,
        'src_ip': socket.inet_ntoa(src_ip),
        'dest_ip': socket.inet_ntoa(dest_ip),
        'data': data[header_length:],
    }


def ipv6_packet(data):
    version_traffic_flow, payload_length, next_header, hop_limit, src_ip, dest_ip = struct.unpack(
        '! I H B B 16s 16s', data[:40])
    return {
        'version': (version_traffic_flow >> 28) & 0xF,
        'src_ip': socket.inet_ntop(socket.AF_INET6, src_ip),
        'dest_ip': socket.inet_ntop(socket.AF_INET6, dest_ip),
        'next_header': next_header,
        'data': data[40:],
    }


threading.Thread(target=check_time).start()
threading.Thread(target=main).start()
