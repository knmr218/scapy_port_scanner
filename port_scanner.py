from scapy.all import *
import argparse
import socket
import re
import random


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
        if not hasattr(namespace, 'scan_types'):
            namespace.scan_types = {}
        for char in values:
            if char == 'S':
                namespace.scan_types['syn'] = True
            elif char == 'U':
                namespace.scan_types['udp'] = True
            elif char == 'V':
                namespace.scan_types['version_detection'] = True
            else:
                raise argparse.ArgumentError(self, f"Invalid scan type: {char}")


class Scanner:
    def __init__(self, ip_address, target_ports):
        self.ip_address = ip_address
        self.target_ports = target_ports
        self.open_ports = {port:"filtered" for port in self.target_ports}
        self.message_displayed = False

    def _display_message(self):
        if not self.message_displayed:
            print("Starting port scan.")
            self.message_displayed = True

    def host_discovery(self):
        self._display_message()
        ping = IP(dst=self.ip_address)/ICMP()
        response = sr1(ping, timeout=2)
        if response == None:
            print("Host might be down or unreachable.")
            print("If you want to skip the ping process, try -Pn.")
            return False
        return True
    
    def syn_scan(self):
        self._display_message()
        # 送信元ポート番号（ランダム）
        source_port = RandShort()
        # 指定されたIPアドレスを送信先とするIPパケットを作成
        ip = IP(dst=self.ip_address)

        for target_port in self.target_ports:
            # TCP 3way handshake
            syn_packet = TCP(sport=source_port, dport=target_port, flags="S")
            syn_ack_response = sr1(ip/syn_packet, timeout=0.05, verbose=0)

            # SYN-ACKパケットのflagが"SA"の場合、ポートが開いていると判断
            if syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 'SA':
                self.open_ports[target_port] = "open"
                
                # RSTパケットを送信して接続をリセット
                rst_packet = TCP(sport=source_port, dport=target_port, flags='R', seq=syn_ack_response.ack)
                send(ip/rst_packet, verbose=0)
    
    def udp_scan(self):
        self._display_message()
    
    def show_result(self):
        for port,result in self.open_ports.items():
            if result == "open":
                print(f"Port {port} is open")



def main():
    # コマンドライン引数を受け取る
    parser = argparse.ArgumentParser(description="This program is the port scanner.")

    parser.add_argument("target", help="Specify target IP address or domain name")
    parser.add_argument("-p", "--ports", type=validate_ports, default='1-1024', help="Specify port ranges")
    parser.add_argument("-p-", "--all-ports", action="store_true", help="Scan all ports")
    parser.add_argument("-Pn", action="store_true", help="Skip connection check with host")
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
    
    scanner = Scanner(ip_address, ports)

    if not args.Pn:
        discovered = scanner.host_discovery()

    if discovered:
        scan_types = getattr(args, 'scan_types', {})
        if scan_types.get('syn') or scan_types == {}:
            scanner.syn_scan()
        if scan_types.get('udp'):
            scanner.udp_scan()
        
        scanner.show_result()
    

if __name__ == "__main__":
    main()