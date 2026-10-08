"""Receive local agent batches and update the Boss Sniffer HTML dashboard."""

import argparse
import json
import logging
from pathlib import Path
import socket

import report

SERVER_IP = "127.0.0.1"
SERVER_PORT = 3333
MAX_MESSAGE_BYTES = 8 * 1024 * 1024


def connection(listening_sock):
    """Read a complete UTF-8 JSON message, which ends when the sender closes."""
    client_sock, _ = listening_sock.accept()
    with client_sock:
        client_sock.settimeout(10)
        chunks = []
        size = 0
        while True:
            chunk = client_sock.recv(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_MESSAGE_BYTES:
                raise ValueError("Capture batch exceeds the 8 MiB limit")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Generate a report from synthetic sample data and exit")
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--settings", type=Path, help="Settings file (defaults to settings.dat or the example)")
    parser.add_argument("--output", type=Path, default=report.DEFAULT_OUTPUT, help="Output HTML path")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if args.demo:
            data = json.loads((report.BASE_DIR / "samples" / "traffic.json").read_text(encoding="utf-8"))
            path = report.generate_report(data, args.output, args.settings)
            print(f"Demo report: {path}")
            return
        data = {}
        path = report.generate_report(data, args.output, args.settings)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listening_sock:
            listening_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listening_sock.bind((SERVER_IP, args.port))
            listening_sock.listen(5)
            logging.info("Listening on %s:%s; report: %s", SERVER_IP, args.port, path)
            while True:
                try:
                    batch = json.loads(connection(listening_sock))
                    report.validate_data(batch)
                except (ValueError, OSError) as error:
                    logging.warning("Rejected capture batch: %s", error)
                    continue
                for ip, values in batch.items():
                    data.setdefault(ip, []).extend(values)
                report.generate_report(data, args.output, args.settings)
                logging.info("Report updated: %s packets", sum(map(len, data.values())))
    except KeyboardInterrupt:
        logging.info("Manager stopped")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Manager failed: {error}\n")


if __name__ == "__main__":
    main()
