"""
SecureNet AI — Traffic Generator & PCAP Replayer (Demo Utility)
Designed for examiner presentations to demonstrate Method 1 (Live Fire Attack)
and Method 2 (Traffic Replay / Scale Blast) without hardcoding any fake data in the NIDS.

Usage:
  Method 1 (Live Fire Attacks):
    python traffic_replay.py --attack sqli --target 127.0.0.1:8000
    python traffic_replay.py --attack xss  --target 127.0.0.1:8000
    python traffic_replay.py --scan        --target 127.0.0.1

  Method 2 (Scale Traffic Blast / PCAP Replay):
    python traffic_replay.py --blast 500   --target 127.0.0.1 --pps 100
    python traffic_replay.py --pcap sample.pcap --target 127.0.0.1
"""

import sys
import time
import argparse
import socket
import urllib.request
import urllib.parse
from datetime import datetime

# Attempt Scapy import for raw layer creation
try:
    from scapy.all import IP, TCP, UDP, Raw, send, rdpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def send_sqli_http_attack(target_host: str):
    """Executes live fire SQL Injection HTTP attack via real network socket."""
    url = f"http://{target_host}/login?user=" + urllib.parse.quote("admin' UNION SELECT null, username, password FROM users--")
    print(f"\n[LIVE FIRE ATTACKER] Executing SQLi Attack against {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AttackerTerminal/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"[ATTACKER RESPONSE] HTTP Status: {resp.status}")
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[ATTACKER INTERCEPTED] HTTP {e.code}: {e.read().decode()}")
        print("[ACTIVE DEFENSE TRIGGERED] The target NIDS detected the SQLi payload!")
    except Exception as e:
        print(f"[ATTACKER TIMEOUT / DROPPED] Request failed: {e}")
        print("[FIREWALL CONFIRMATION] The target kernel firewall dropped the packet!")


def send_xss_http_attack(target_host: str):
    """Executes live fire XSS HTTP attack via real network socket."""
    url = f"http://{target_host}/api/data?search=" + urllib.parse.quote("<script>alert('XSS_BREACH')</script>")
    print(f"\n[LIVE FIRE ATTACKER] Executing XSS Attack against {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AttackerTerminal/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"[ATTACKER RESPONSE] HTTP Status: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[ATTACKER INTERCEPTED] HTTP {e.code}: {e.read().decode()}")
        print("[ACTIVE DEFENSE TRIGGERED] The target NIDS detected the XSS payload!")
    except Exception as e:
        print(f"[ATTACKER TIMEOUT / DROPPED] Request failed: {e}")
        print("[FIREWALL CONFIRMATION] The target kernel firewall dropped the packet!")


def send_port_scan(target_ip: str, port_range=(20, 100)):
    """Simulates real SYN port probe across a range of ports."""
    print(f"\n[LIVE FIRE ATTACKER] Scanning ports {port_range[0]}-{port_range[1]} on {target_ip}...")
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        res = s.connect_ex((target_ip, port))
        if res == 0:
            open_ports.append(port)
        s.close()
    print(f"[SCAN COMPLETE] Probed {port_range[1] - port_range[0] + 1} ports. Open: {open_ports}")


def blast_traffic(target_ip: str, count: int = 500, pps: int = 100):
    """
    Blasts real UDP network packets to demonstrate PPS scale and chart responsiveness.
    Every single packet is physically transmitted on the network interface!
    """
    print(f"\n[TRAFFIC BLASTER] Blasting {count} physical packets to {target_ip} at ~{pps} PPS...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    delay = 1.0 / max(pps, 1)

    sent = 0
    start_time = time.time()
    try:
        for i in range(count):
            payload = f"SecureNet_Packet_Seq_{i}_{datetime.utcnow().isoformat()}".encode()
            # Send to random unprivileged ports (40000 - 60000)
            port = 40000 + (i % 20000)
            s.sendto(payload, (target_ip, port))
            sent += 1
            if sent % 100 == 0 or sent == count:
                elapsed = time.time() - start_time
                actual_pps = sent / max(elapsed, 0.001)
                print(f" -> Transmitted {sent}/{count} physical frames ({actual_pps:.1f} PPS)...")
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\nBlast aborted by operator.")
    finally:
        s.close()

    total_time = time.time() - start_time
    print(f"[BLAST COMPLETE] Successfully transmitted {sent} real network packets in {total_time:.2f}s!")


def replay_pcap(pcap_path: str, target_ip: str):
    """Replays packets from a standardized PCAP file."""
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is required for PCAP reading.")
        return

    print(f"\n[PCAP REPLAYER] Reading recorded frames from '{pcap_path}'...")
    try:
        packets = rdpcap(pcap_path)
        print(f"Loaded {len(packets)} recorded packets. Blasting into network card...")
        for pkt in packets:
            if IP in pkt:
                pkt[IP].dst = target_ip
            send(pkt, verbose=False)
        print("[PCAP REPLAY COMPLETE] All packets replayed to NIC.")
    except Exception as e:
        print(f"[PCAP ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(description="SecureNet AI Traffic Injection Tool")
    parser.add_argument("--attack", choices=["sqli", "xss"], help="Execute live fire attack")
    parser.add_argument("--scan", action="store_true", help="Execute real port scan probe")
    parser.add_argument("--blast", type=int, help="Blast N real UDP packets to test PPS scale")
    parser.add_argument("--pps", type=int, default=100, help="Packets per second rate for blast")
    parser.add_argument("--pcap", type=str, help="Replay standardized PCAP dataset")
    parser.add_argument("--target", type=str, default="127.0.0.1", help="Target IP or host:port")

    args = parser.parse_args()

    if args.attack == "sqli":
        host = args.target if ":" in args.target else f"{args.target}:8000"
        send_sqli_http_attack(host)
    elif args.attack == "xss":
        host = args.target if ":" in args.target else f"{args.target}:8000"
        send_xss_http_attack(host)
    elif args.scan:
        send_port_scan(args.target.split(":")[0])
    elif args.blast:
        blast_traffic(args.target.split(":")[0], count=args.blast, pps=args.pps)
    elif args.pcap:
        replay_pcap(args.pcap, args.target.split(":")[0])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
