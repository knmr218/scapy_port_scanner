from scapy.all import *
import argparse
import socket
import re
import random

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
    # 特定の形式で指定されたポート番号を数値の集合として返す
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def validate_ports(port_string):
    # ポート番号の指定が正しい形式かどうか検証
    pattern = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')
    if not pattern.match(port_string):
        raise argparse.ArgumentTypeError("Invalid format.")
    return port_string

class ScanTypeAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # 指定されたスキャンタイプを列挙
        for char in values:
            if char == 'S':
                namespace.SYN = True
            elif char == 'T':
                namespace.TCP = True
            elif char == 'V':
                namespace.VERSION = True
            else:
                raise argparse.ArgumentError(self, f"Invalid scan type: {char}")

def resolve_ip(target):
    try:
        # IPアドレスとして解決を試みる
        socket.inet_aton(target)
        return target
    except socket.error:
        try:
            # ドメイン名として解決を試みる
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Invalid input: {target}")

def main():
    # コマンドライン引数を受け取る
    parser = argparse.ArgumentParser(description="This program is the port scanner.")

    parser.add_argument("target", help="Specify target IP address or domain name")
    parser.add_argument("-p", "--ports", type=validate_ports, default='1-1024', help="Specify port ranges")
    parser.add_argument("-p-", "--all-ports", action="store_true", help="Scan all ports")
    parser.add_argument('-s', '--scan', action=ScanTypeAction, help="Specify scan type (ex: -sS, -sT, -sU)")

    args = parser.parse_args()


    # 入力をIPアドレスに変換    
    try:
        ip_address = resolve_ip(args.target)
    except ValueError as e:
        print(e)
        return
        

    # 指定されたポートをリストに格納
    ports = parse_ports(args.ports)
    if args.all_ports:
        ports = list(range(1,65536))


    conf.verb = 0

    # 送信元ポート番号（ランダム）
    sport = RandShort()
    # 送信先ポート番号
    target_port = 443
    # 指定されたIPアドレスを送信先とするIPパケットを作成
    ip = IP(dst=ip_address)

    # TCP 3way handshake
    syn_packet = TCP(sport=sport, dport=target_port, flags="S", seq=seq)
    syn_ack_response = sr1(ip/syn_packet)
    if syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 'SA':
        print("SYN-ACK packet received.")

        ACK = TCP(sport=sport, dport=target_port, flags="A", seq=syn_ack_response.ack, ack=syn_ack_response.seq + 1)
        send(ip/ACK)

        print("ACK packet sent, connection established.")


if __name__ == "__main__":
    main()