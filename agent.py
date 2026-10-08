"""Capture local IPv4 TCP/UDP traffic and send packet metadata to the manager."""

import argparse
from ipaddress import IPv4Address
import json
import logging
import platform
import socket
import subprocess

import requests
from scapy.all import Ether, IP, TCP, UDP, conf, get_if_addr, sniff
from scapy.error import Scapy_Exception

SERVER_PORT = 3333
SERVER_IP = "127.0.0.1"


def country_find(ip):
    """Best-effort lookup through the original provider; called only on opt-in."""
    if not IPv4Address(ip).is_global:
        return "Unknown"
    try:
        response = requests.get("http://ip-api.com/json/" + ip, timeout=3)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success" and isinstance(data.get("country"), str):
            return data["country"]
    except (requests.RequestException, ValueError, AttributeError):
        pass
    return "Unknown"


def filter1(packet):
    """Keep IPv4 TCP and UDP packets."""
    return IP in packet and (UDP in packet or TCP in packet)


def program_find(ip, netstat_output):
    """Preserve the original Windows netstat-based, best-effort app lookup."""
    lines = netstat_output.splitlines()
    for index, line in enumerate(lines):
        fields = line.split()
        if len(fields) >= 3 and fields[2].startswith(ip + ":"):
            for detail in lines[index + 1:index + 3]:
                if detail.strip().startswith("[") and detail.strip().endswith("]"):
                    return detail.strip()[1:-1]
                if detail.strip().startswith(("TCP", "UDP")):
                    break
    return "Unknown"


def packets_to_data(packets, local_ip, geolocate=False, netstat_output=""):
    """Keep the original IP -> [port, direction, length, country, app, MAC] format."""
    dict1 = {}
    dict_of_countries = {}
    for packet in packets:
        if not filter1(packet):
            continue
        if packet[IP].src == local_ip:
            remote_ip, outgoing = packet[IP].dst, True
        elif packet[IP].dst == local_ip:
            remote_ip, outgoing = packet[IP].src, False
        else:
            continue
        transport = packet[TCP] if TCP in packet else packet[UDP]
        port = transport.dport if outgoing else transport.sport
        if remote_ip not in dict_of_countries:
            dict_of_countries[remote_ip] = country_find(remote_ip) if geolocate else "Unknown"
        mac = "Unknown"
        if Ether in packet:
            mac = packet[Ether].dst if outgoing else packet[Ether].src
        value = [port, str(outgoing), len(packet), dict_of_countries[remote_ip],
                 program_find(remote_ip, netstat_output), mac]
        dict1.setdefault(remote_ip, []).append(value)
    return dict1


def sniff1(count=500, interface=None, local_ip=None, timeout=10, geolocate=False):
    """Capture a bounded batch on the selected interface and serialize metadata."""
    interface = interface or conf.iface
    local_ip = local_ip or get_if_addr(interface)
    if local_ip == "0.0.0.0":
        raise ValueError("The selected interface has no IPv4 address; use --interface / --local-ip")
    packets = sniff(count=count, lfilter=filter1, iface=interface, timeout=timeout)
    output = ""
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["netstat", "-nb"], text=True,
                                             errors="replace", timeout=10)
        except (OSError, subprocess.SubprocessError) as error:
            logging.warning("Application lookup unavailable: %s", error)
    return json.dumps(packets_to_data(packets, local_ip, geolocate, output))


def send_info(information, server_ip=SERVER_IP, server_port=SERVER_PORT):
    """One JSON batch per connection; closing the socket marks the end of the batch."""
    with socket.create_connection((server_ip, server_port), timeout=10) as sock:
        sock.sendall(information.encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="Network interface to capture on")
    parser.add_argument("--local-ip", type=IPv4Address, help="Override the interface's local IPv4 address")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Local manager port (default: 3333)")
    parser.add_argument("--count", type=int, default=500, help="Maximum packets per batch (default: 500)")
    parser.add_argument("--timeout", type=float, default=10, help="Seconds per capture batch (default: 10)")
    parser.add_argument("--once", action="store_true", help="Send one batch and exit")
    parser.add_argument("--geolocate", action="store_true",
                        help="Look up public IPs using ip-api.com over HTTP (external requests)")
    args = parser.parse_args()
    if args.count < 1 or args.timeout <= 0 or not 1 <= args.port <= 65535:
        parser.error("count and timeout must be positive; port must be between 1 and 65535")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        while True:
            info = sniff1(args.count, args.interface, str(args.local_ip) if args.local_ip else None,
                          args.timeout, args.geolocate)
            send_info(info, server_port=args.port)
            logging.info("Sent a capture batch to %s:%s", SERVER_IP, args.port)
            if args.once:
                return
    except KeyboardInterrupt:
        logging.info("Capture stopped")
    except (OSError, ValueError, Scapy_Exception) as error:
        parser.exit(1, f"Capture failed: {error}\nCheck capture permissions and that manager.py is running.\n")


if __name__ == "__main__":
    main()
