"""One-connection, loopback-only TCP test service for the WSL Nmap smoke run.

It serves no application and contains no vulnerability. It accepts a single TCP
connection, sends a harmless response, and exits. A 90-second accept timeout
also ensures it cannot remain running indefinitely if the scan is not started.
"""

from __future__ import annotations

import socketserver

HOST = "127.0.0.1"
PORT = 8080


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(1.0)
        try:
            self.request.recv(1024)
        except (TimeoutError, OSError):
            pass
        try:
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Length: 25\r\n"
                b"Connection: close\r\n\r\n"
                b"ProofPath local test only"
            )
        except OSError:
            pass


class _OneShotServer(socketserver.TCPServer):
    allow_reuse_address = True


def main() -> int:
    with _OneShotServer((HOST, PORT), _Handler) as server:
        server.timeout = 90
        print(f"READY {HOST}:{PORT}", flush=True)
        server.handle_request()
    print("STOPPED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
