import json
import unittest
from unittest.mock import patch

from scapy.all import ARP, Ether, IP, TCP, UDP
import requests

import agent


class AgentTests(unittest.TestCase):
    def test_tcp_and_udp_use_remote_port_and_direction(self):
        packets = [
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="198.51.100.1")/TCP(sport=50000, dport=443),
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="198.51.100.1", dst="192.0.2.1")/TCP(sport=443, dport=50000),
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="198.51.100.2")/UDP(sport=50001, dport=53),
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="198.51.100.2", dst="192.0.2.1")/UDP(sport=53, dport=50001),
        ]
        data = agent.packets_to_data(packets, "192.0.2.1")
        self.assertEqual([r[:2] for r in data["198.51.100.1"]], [[443, "True"], [443, "False"]])
        self.assertEqual([r[:2] for r in data["198.51.100.2"]], [[53, "True"], [53, "False"]])
        self.assertEqual(data["198.51.100.1"][0][2], 54)

    def test_exact_address_match_and_non_ip_filtering(self):
        packets = [IP(src="192.0.2.10", dst="198.51.100.1")/TCP(), Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/ARP()]
        self.assertEqual(agent.packets_to_data(packets, "192.0.2.1"), {})

    def test_packet_without_ethernet_is_retained(self):
        data = agent.packets_to_data([IP(src="192.0.2.1", dst="198.51.100.1")/UDP(dport=53)], "192.0.2.1")
        self.assertEqual(data["198.51.100.1"][0][5], "Unknown")

    def test_geolocation_failure_does_not_drop_traffic(self):
        with patch("agent.requests.get", side_effect=requests.Timeout):
            self.assertEqual(agent.country_find("8.8.8.8"), "Unknown")

    def test_private_addresses_need_no_geolocation_request(self):
        with patch("agent.requests.get", side_effect=AssertionError("Unexpected network call")):
            self.assertEqual(agent.country_find("192.168.1.1"), "Unknown")

    def test_short_capture_does_not_assume_500_packets(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.1")/TCP(dport=443)
        with patch("agent.sniff", return_value=[packet]), patch("agent.platform.system", return_value="Linux"):
            data = json.loads(agent.sniff1(count=10, local_ip="192.0.2.1"))
        self.assertEqual(len(data["198.51.100.1"]), 1)

    def test_windows_application_lookup_uses_exact_remote_address(self):
        output = "  TCP  192.0.2.1:50000  198.51.100.10:443  ESTABLISHED\n [other.exe]\n"
        output += "  TCP  192.0.2.1:50001  198.51.100.1:443  ESTABLISHED\n [browser.exe]\n"
        self.assertEqual(agent.program_find("198.51.100.1", output), "browser.exe")
        self.assertEqual(agent.program_find("203.0.113.1", output), "Unknown")


if __name__ == "__main__":
    unittest.main()
