import socket
import struct
import textwrap
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

def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        #dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        eth = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],eth[2]))
        print('eth', eth[3])
        #print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
        
        # Ethernet Type 8: ARP
        if eth[2] == 8:
            arp_data = arp_packet(data)
            print("\nARP Packet:")
            # print(f"ARP Opcode: {arp_data['opcode']}")
            # print(f"Sender MAC: {arp_data['sender_mac']}, Sender IP: {arp_data['sender_ip']}")
            # print(f"Target MAC: {arp_data['target_mac']}, Target IP: {arp_data['target_ip']}")
            protocol_count['ARP'] += 1

        # Ethernet Type 2048: IPv4
        elif eth[2] == 2048:
            ipv4_data = ipv4_packet(data)
            print("\nIPv4 Packet:")
            # print(f"Version: {ipv4_data['version']}, Header Length: {ipv4_data['header_length']}")
            # print(f"TTL: {ipv4_data['ttl']}, Protocol: {ipv4_data['protocol']}")
            # print(f"Source IP: {ipv4_data['src_ip']}, Destination IP: {ipv4_data['dest_ip']}")
            protocol_count['IPv4'] += 1
            
            # Protocol 1: ICMP
            if ipv4_data['protocol'] == 1:
                icmp_data = icmp_packet(ipv4_data['data'])
                print("\nICMP Packet:")
                # print(f"Type: {icmp_data['type']}, Code: {icmp_data['code']}")
                protocol_count['ICMP'] += 1
                
            # Protocol 6: TCP
            elif ipv4_data['protocol'] == 6:
                tcp_data = tcp_segment(ipv4_data['data'])
                print("\nTCP Segment:")
                # print(f"Source Port: {tcp_data['src_port']}, Destination Port: {tcp_data['dest_port']}")
                protocol_count['TCP'] += 1

            # Protocol 17: UDP
            elif ipv4_data['protocol'] == 17:
                udp_data = udp_segment(ipv4_data['data'])
                print("\nUDP Segment:")
                # print(f"Source Port: {udp_data['src_port']}, Destination Port: {udp_data['dest_port']}")
                protocol_count['UDP'] += 1
                
        # Ethernet Type 34525: IPv6
        elif eth[2] == 34525:
            ipv6_data = ipv6_packet(data)
            print("\nIPv6 Packet:")
            # print(f"Version: {ipv6_data['version']}")
            # print(f"Source IP: {ipv6_data['src_ip']}, Destination IP: {ipv6_data['dest_ip']}")
            # print(f"Next Header: {ipv6_data['next_header']}")
            protocol_count['IPv6'] += 1

            # Next Header 58: ICMPv6
            if ipv6_data['next_header'] == 58:
                icmpv6_data = icmpv6_packet(ipv6_data['data'])
                print("\nICMPv6 Packet:")
                #print(f"Type: {icmpv6_data['type']}, Code: {icmpv6_data['code']}")
                protocol_count['ICMPv6'] += 1

        print("\nProtocol Count:")
        for protocol, count in protocol_count.items():
            print(f"{protocol}: {count}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def arp_packet(data):
    opcode, sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! 2s 6s 4s 6s 4s', data)
    return {
        'opcode': int.from_bytes(opcode, byteorder='big'),
        'sender_mac': get_mac_addr(sender_mac),
        'sender_ip': socket.inet_ntoa(sender_ip),
        'target_mac': get_mac_addr(target_mac),
        'target_ip': socket.inet_ntoa(target_ip),
    }

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': protocol,
        'src_ip': socket.inet_ntoa(src_ip),
        'dest_ip': socket.inet_ntoa(dest_ip),
        'data': data[header_length:],
    }

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return {'type': icmp_type, 'code': code, 'checksum': checksum}

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'sequence': sequence,
        'acknowledgment': acknowledgment,
        'flags': flags,
        'data': data[offset:],
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

def icmpv6_packet(data):
    icmpv6_type, code, checksum = struct.unpack('! B B H', data[:4])
    return {'type': icmpv6_type, 'code': code, 'checksum': checksum}

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'data': data[8:],
    }

if __name__ == "__main__":
    main()
