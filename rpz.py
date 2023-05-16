import argparse
import socket
import sys
import threading
import time
import queue

GREEN = "\033[32m"
BOLD = "\033[1m"
BLUE = "\033[94m"
RED = "\033[91m"
END = "\033[0m"


class PortScanner:
    def __init__(self, target, thread=5, port_range=None):
        self.target = target
        self.thread = thread
        self.ports = range(1, 65536) if port_range is None else range(*map(int, port_range.split("-")))
        self.start_time = None

    def _printer(self, text):
        sys.stdout.write(text + "               \r")
        sys.stdout.flush()

    def _scan(self, port):
        space = " " * (10 - len(str(port)))
        self._printer("Testing Port: " + str(port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((self.target, port)):
                return
            try:
                service = socket.getservbyport(port)
                print(str(port) + "/TCP" + space + service)
            except socket.error:
                print(str(port) + "/TCP" + space + "Unknown")

    def _worker(self):
        while True:
            try:
                port = self._port_queue.get(block=False)
            except queue.Empty:
                break
            self._scan(port)
            self._port_queue.task_done()

    def run(self):
        print(RED + """
        --~~SecHex~~ ->	https://github.com/SecHex
        """ + END)

        print(GREEN + "[+] Target: " + END + self.target)
        print(GREEN + "[+] Threads: " + END + str(self.thread))
        print(GREEN + "[+] Ports: " + END + f"{self.ports.start}-{self.ports.stop-1}")
        print(BOLD + "\n[+] Start The Scan\n" + END)
        print("PORT          SERVICE")
        print("----          -------")

        self.start_time = time.time()
        self._port_queue = queue.Queue()
        for port in self.ports:
            self._port_queue.put(port)

        threads = []
        for _ in range(self.thread):
            thread = threading.Thread(target=self._worker)
            thread.start()
            threads.append(thread)

        self._port_queue.join()
        for thread in threads:
            thread.join()

        took = time.time() - self.start_time
        minutes, seconds = divmod(int(took), 60)
        print(BLUE + f"[+] Took: {minutes}:{seconds:02}" + END)


def main():
    print(RED + "SecHex - Portscanner" + END)
    target = input("IP address or hostname: ")
    thread = int(input("threads to use (default is 5): ") or "5")
    port_range = input("Please enter the range of ports to scan (default is 1-65535): ") or "1-65535"

    scanner = PortScanner(target, thread, port_range)
    scanner.run()

if __name__ == '__main__':
    main()
