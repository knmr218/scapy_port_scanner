from scapy.all import *
import argparse
import socket
import re
import random
import asyncio


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
            elif char == 'X':
                namespace.scan_types['xmas'] = True
            elif char == 'V':
                namespace.scan_types['version_detection'] = True
            else:
                raise argparse.ArgumentError(self, f"Invalid scan type: {char}")



class Scanner:
    def __init__(self, ip_address, target_ports):
        self.ip_address = ip_address
        self.target_ports = target_ports
        self.scan_types = []
        self.open_ports = {} # port:"closed" for port in self.target_ports
        self.message_displayed = False

    def _display_message(self):
        if not self.message_displayed:
            print("Starting port scan.")
            self.message_displayed = True

    def host_discovery(self):
        self._display_message()
        ping = IP(dst=self.ip_address)/ICMP()
        response = sr1(ping, timeout=2)
        if response is None:
            print("Host might be down or unreachable.")
            print("If you want to skip the ping process, try -Pn.")
            return False
        return True
    
    async def scan_ports(self):
        tasks = []
        for port in self.target_ports:
            if "syn" in self.scan_types:
                tasks.append(self.syn_scan(port))
            if "udp" in self.scan_types:
                tasks.append(self.udp_scan(port))
            if "xmas" in self.scan_types:
                tasks.append(self.xmas_scan(port))
        await asyncio.gather(*tasks)

    async def syn_scan(self, target_port):
        self._display_message()
        # 送信元ポート番号（ランダム）
        source_port = RandShort()
        # 指定されたIPアドレスを送信先とするIPパケットを作成
        ip = IP(dst=self.ip_address)

        # TCP 3way handshake
        packet = TCP(sport=source_port, dport=target_port, flags="S")
        response = sr1(ip/packet, timeout=0.05, verbose=0)
        key_name = str(target_port)+"/tcp"
        scanned = key_name in self.open_ports

        # SYN-ACKパケットのflagが"SA"の場合、ポートが開いていると判断
        # "RA"の場合は閉じていると判断
        # すでに別のスキャンでの結果が出ている場合、結果を優先順位に従って修正する
        if response != None:
            if response.haslayer(TCP) and response[TCP].flags == 'SA':
                self.open_ports[key_name] = "open"
            elif response.haslayer(TCP) and response[TCP].flags == 'RA':
                if not (scanned and self.open_ports[key_name] == "open"):
                    self.open_ports[key_name] = "closed"
            elif response.haslayer(TCP) or response.haslayer(ICMP):
                if not (scanned and self.open_ports[key_name] in ["open", "closed", "open|filtered", "unknown"]):
                    self.open_ports[key_name] = "filtered"
            else:
                if not (scanned and self.open_ports[key_name] in ["open", "closed"]):
                    self.open_ports[key_name] = "unknown"
                    print(response.summary())

            # RSTパケットを送信して接続をリセット
            rst_packet = TCP(sport=source_port, dport=target_port, flags='R', seq=response.ack)
            send(ip/rst_packet, verbose=0)
    
    async def udp_scan(self, target_port):
        self._display_message()
        # パケットの作成
        packet = IP(dst=self.ip_address)/UDP(dport=target_port)
        response = sr1(packet, timeout=2, verbose=False)
        key_name = str(target_port)+"/udp"

        # レスポンスがなければ、ポートが空いているかフィルタリングされていると判断する
        # ポートが閉じている場合は ICMP Port Unreachable が返ってくる
        if response is None:
            self.open_ports[key_name] = "open|filtered"
        elif response.haslayer(ICMP):
            self.open_ports[key_name] = "closed"
        elif response.haslayer(UDP):
            self.open_ports[key_name] = "open|filtered"
        else:
            self.open_ports[key_name] = "unknown"
            print(response.summary())
    
    async def xmas_scan(self, target_port):
        self._display_message()
        # パケットの作成
        pkt = IP(dst=self.ip_address)/TCP(dport=target_port, flags="FPU")
        response = sr1(pkt, timeout=1, verbose=0)

        key_name = str(target_port)+"/tcp"
        scanned = key_name in self.open_ports
        
        # レスポンスがなければ、ポートが空いているかフィルタリングされていると判断する
        if response is None:
            if not (scanned and self.open_ports[key_name] in ["open", "closed"]):
                self.open_ports[key_name] = "open|filtered"
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == "RA":
            if not (scanned and self.open_ports[key_name] == "open"):
                self.open_ports[key_name] = "Closed"
        elif response.haslayer(ICMP):
            if not (scanned and self.open_ports[key_name] in ["open", "closed", "open|filtered", "unknown"]):
                self.open_ports[key_name] = "filtered"
        else:
            if not (scanned and self.open_ports[key_name] in ["open", "closed"]):
                self.open_ports[key_name] = "unknown"
                print(response.summary())
    
    def show_result(self):
        for port,result in self.open_ports.items():
            if "open" in result:
                print(f"Port {port} is {result}")



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

    discovered = True
    if not args.Pn:
        discovered = scanner.host_discovery()

    if discovered:
        scan_types = getattr(args, 'scan_types', {})
        if scan_types.get('syn') or scan_types == {}:
            scanner.scan_types.append("syn")
        if scan_types.get('udp'):
            scanner.scan_types.append("udp")
        if scan_types.get('xmas'):
            scanner.scan_types.append("xmas")
        
        asyncio.run(scanner.scan_ports())
        scanner.show_result()
    

if __name__ == "__main__":
    main()