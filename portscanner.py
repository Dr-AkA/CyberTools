#!/usr/bin/env python3

import argparse
import socket
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any

# === Configuration ===
DEFAULT_TIMEOUT = 1.5
MAX_THREADS = 200
BANNER_READ_BYTES = 1024
socket.setdefaulttimeout(DEFAULT_TIMEOUT)

# === Logging ===
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class PortScanner:
    def __init__(self, host: str, ports: List[int], threads: int = MAX_THREADS, banner: bool = False):
        self.host = host
        self.ports = ports
        self.threads = min(len(ports), threads)
        self.banner = banner
        self.results = []

        self.ip = self._resolve_host()
        if not self.ip:
            raise ValueError(f"Could not resolve host: {host}")

    def _resolve_host(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return None

    def scan(self):
        logging.info(f"Scanning {self.host} ({self.ip}) on ports: {self.ports}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, port): port for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)

    def _scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        result = {'port': port, 'status': 'closed'}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(DEFAULT_TIMEOUT)
                if sock.connect_ex((self.ip, port)) == 0:
                    result['status'] = 'open'
                    if self.banner:
                        try:
                            sock.sendall(b"\r\n")
                            banner = sock.recv(BANNER_READ_BYTES).decode(errors='ignore').strip()
                            if banner:
                                result['banner'] = banner
                        except Exception as e:
                            result['banner'] = f"Error reading banner: {str(e)}"
                    logging.info(f"Port {port} is OPEN")
                    return result
        except Exception as e:
            logging.debug(f"Error scanning port {port}: {e}")
        return None

    def to_json(self) -> str:
        return json.dumps({
            'host': self.host,
            'ip': self.ip,
            'ports': self.results
        }, indent=2)

    def print_summary(self):
        print("\n=== Scan Summary ===")
        print(f"Host: {self.host} ({self.ip})")
        print(f"Open Ports: {len(self.results)}")
        for entry in sorted(self.results, key=lambda x: x['port']):
            line = f"  Port {entry['port']} - OPEN"
            if 'banner' in entry:
                line += f" | Banner: {entry['banner']}"
            print(line)


def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    return sorted(ports)


def parse_args():
    parser = argparse.ArgumentParser(description='Advanced multithreaded port scanner with banner grabbing.')
    parser.add_argument('-H', '--host', required=True, help='Target hostname or IP')
    parser.add_argument('-p', '--ports', required=True, help='Ports (e.g. 22,80,443 or 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=MAX_THREADS, help='Maximum number of threads')
    parser.add_argument('--banner', action='store_true', help='Attempt to grab service banners')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        ports = parse_ports(args.ports)
        scanner = PortScanner(args.host, ports, threads=args.threads, banner=args.banner)
        scanner.scan()

        if args.json:
            print(scanner.to_json())
        else:
            scanner.print_summary()
    except Exception as e:
        logging.error(f"Error: {e}")


if __name__ == '__main__':
    main()
