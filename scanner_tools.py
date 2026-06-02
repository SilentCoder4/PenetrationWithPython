import socket
from concurrent.futures import ThreadPoolExecutor
import sys


class PortScanner:
    def __init__(self, target, ports=None):
        self.target = target
        self.ports = ports if ports else range(1, 65536)

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)

                if sock.connect_ex((self.target, port)) == 0:
                    print(f"[OPEN] {port}")

        except socket.gaierror:
            print("Invalid hostname.")
        except socket.timeout:
            pass
        except Exception:
            pass

    def run(self):
        try:
            print(f"Scanning {self.target}...")

            with ThreadPoolExecutor(max_workers=200) as executor:
                executor.map(self.scan_port, self.ports)

            print("Scan complete.")

        except KeyboardInterrupt:
            print("\nScan stopped by user.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    scanner = PortScanner("127.0.0.1")  # scans all ports by default
    scanner.run()