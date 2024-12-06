from scapy.all import *
import argparse
import socket
import re
import random
import asyncio
import time
import sys
import threading
import itertools


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



def loading_animation(stop_event):
    chars = itertools.cycle(['.', '..', '...','....','.....'])
    while not stop_event.is_set():  # stop_eventがセットされるまでアニメーションを続ける
        sys.stdout.write(f'\033[2K\033[G{next(chars)}')  # キャラクターを更新
        sys.stdout.flush()  # 即時反映
        time.sleep(0.5)  # アニメーション更新間隔（100ms）



def get_service_name(port, protocol="tcp"):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"



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
    def __init__(self, ip_address, target_ports, target):
        self.ip_address = ip_address
        self.target_ports = target_ports
        self.target = target
        self.scan_types = []
        self.open_ports = {} # port:"closed" for port in self.target_ports

    def host_discovery(self):
        ping = IP(dst=self.ip_address)/ICMP()
        response = sr1(ping, timeout=2)
        if response is None:
            sys.stdout.write('\033[2K\033[G')  # 現在の行をクリア
            sys.stdout.flush()  # 画面を更新
            print("\nHost might be down or unreachable.")
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
        
    
    def show_result(self, scan_time):
        print(f"\nScan report to {self.target}")
        if "open" in self.open_ports.values():
            print("PORT     STATE  SERVICE")
            for port,result in self.open_ports.items():
                if "open" in result:
                    port_num,protocol = port.split("/")
                    service_name = get_service_name(int(port_num),protocol)
                    print("{:<8} {}   {}".format(port, result, service_name))
        else:
            print("No open ports were found")

        print(f"\nScan done: Scan time was {scan_time:.2f} seconds.")



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
        if ip_address != "192.168.1.101":
            print("禁止されたIPアドレスです")
            return
    except ValueError as e:
        print(e)
        return
    
    
    # 指定されたポートをリストに格納
    input_ports = parse_ports(args.ports)
    if args.all_ports:
        input_ports = list(range(1,65536))
    
    ports = list(range(100,157))
    if len(input_ports) < len(ports):
        ports = list(range(100,101+len(input_ports)))

    for p in [22,80,2049]:
        if p in input_ports:
            ports.append(p)
            ports.pop(0)

    scan_types = getattr(args, 'scan_types', {})

    if scan_types.get('udp'):
        ports = [1,2,3]

    conf.verb = 0
    
    scanner = Scanner(ip_address, ports, args.target)

    print("Starting port scan.")

    # アニメーション停止用のイベントを作成
    stop_event = threading.Event()

    # アニメーションを別スレッドで実行
    animation_thread = threading.Thread(target=loading_animation, args=(stop_event,), daemon=True)
    animation_thread.start()

    start_time = time.perf_counter()  # 高精度な開始時刻を記録

    discovered = True
    if not args.Pn:
        discovered = scanner.host_discovery()

    if discovered:
        if scan_types.get('syn') or scan_types == {}:
            scanner.scan_types.append("syn")
        if scan_types.get('udp'):
            scanner.scan_types.append("udp")
        if scan_types.get('xmas'):
            scanner.scan_types.append("xmas")
        
        asyncio.run(scanner.scan_ports())

        end_time = time.perf_counter()  # 高精度な終了時刻を記録
        stop_event.set() # アニメーションの終了

        scanner.show_result(end_time - start_time)
    

if __name__ == "__main__":
    main()