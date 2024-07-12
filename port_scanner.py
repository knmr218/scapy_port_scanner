from scapy.all import *
import argparse
import socket
import re

# def tcp_syn_scan(target_ip, port_range):
#     open_ports = []
#     for port in port_range:
#         pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
#         response = sr1(pkt, timeout=1, verbose=0)
#         if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
#             open_ports.append(port)
#             sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)  # Reset connection
#     return open_ports

def parse_ports(port_string):
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def validate_ports(port_string):
    pattern = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')
    if not pattern.match(port_string):
        raise argparse.ArgumentTypeError("Invalid format.")
    return port_string

class ScanTypeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        for char in values:
            if char == 'S':
                namespace.SYN = True
            elif char == 'T':
                namespace.TCP = True
            elif char == 'V':
                namespace.VERSION = True
            else:
                raise argparse.ArgumentError(self, f"無効なスキャンタイプ: {char}")

def main():
    parser = argparse.ArgumentParser(description="This program is the port scanner.")

    parser.add_argument("ip_address", help="Specify target IP address")
    parser.add_argument("-p", "--ports", type=validate_ports, default='1-1024', help="Specify port ranges")
    parser.add_argument("-p-", "--all-ports", action="store_true", help="Scan all ports")
    parser.add_argument('-s', '--scan', action=ScanTypeAction, help="Specify scan type (ex: -sS, -sT, -sU)")

    args = parser.parse_args()

    ip_address = args.ip_address
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        print(f"Error: Invalid IP address: {ip_address}")
        return
        

    ports = parse_ports(args.ports)
    if args.all_ports:
        ports = list(range(1,65536))

    if args.SYN:
        print("True syn")
    if args.VERSION:
        print("True version")

    ping = IP(dst="www.google.com")/ICMP()
    ans = sr1(ping)
    ans.show()

if __name__ == "__main__":
    main()