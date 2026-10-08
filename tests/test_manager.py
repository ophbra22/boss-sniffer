from concurrent.futures import ThreadPoolExecutor
import json
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import agent
import manager


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]

    def test_large_fragmented_message_is_not_truncated(self):
        message = json.dumps({"198.51.100.1": [[443, "True", 60, "Unknown", "app", "mac"]] * 3000})
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(manager.connection, self.listener)
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
                for offset in range(0, len(message), 777):
                    client.sendall(message[offset:offset+777].encode())
            self.assertEqual(result.result(timeout=5), message)

    def test_sender_closes_batch_and_listener_accepts_next_batch(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            for _ in range(2):
                result = pool.submit(manager.connection, self.listener)
                agent.send_info('{}', server_port=self.port)
                self.assertEqual(result.result(timeout=5), '{}')

    def test_oversized_message_is_rejected(self):
        with patch("manager.MAX_MESSAGE_BYTES", 8), ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(manager.connection, self.listener)
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
                client.sendall(b"123456789")
            with self.assertRaises(ValueError):
                result.result(timeout=5)

    def test_manager_recovers_from_bad_batch_and_renders_real_socket_input(self):
        self.listener.close()
        root = Path(manager.__file__).parent
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.html"
            process = subprocess.Popen(
                [sys.executable, "-u", str(root / "manager.py"), "--port", str(self.port),
                 "--output", str(output), "--settings", str(root / "settings.example.dat")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=temp,
            )
            try:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    line = pool.submit(process.stdout.readline).result(timeout=10)
                self.assertIn("Listening on", line)
                agent.send_info('not json', server_port=self.port)
                from scapy.all import IP, UDP
                data = agent.packets_to_data([
                    IP(src="192.0.2.1", dst="203.0.113.10")/UDP(sport=50000, dport=53)
                ], "192.0.2.1")
                agent.send_info(json.dumps(data), server_port=self.port)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    html = output.read_text(encoding="utf-8")
                    if "Blacklist traffic detected" in html:
                        break
                    time.sleep(0.02)
                self.assertIn("Blacklist traffic detected for: local-agent:127.0.0.1", html)
                self.assertIn('labels: ["203.0.113.10"]', html)
                self.assertNotIn("%%", html)
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
