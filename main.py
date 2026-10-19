
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import (
    sniff,
    wrpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    ARP,
    get_if_list,
)

# Store captured packets and statistics
captured_packets = []
protocol_counts = Counter()
source_counts = Counter()
destination_counts = Counter()
displayed_count = 0


def get_protocol(packet):
    """Identify the main protocol in a packet."""
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IP):
        return "IP"
    if packet.haslayer(IPv6):
        return "IPv6"
    return "OTHER"


def get_addresses(packet):
    """Return source and destination addresses."""
    if packet.haslayer(IP):
        layer = packet[IP]
        return layer.src, layer.dst

    if packet.haslayer(IPv6):
        layer = packet[IPv6]
        return layer.src, layer.dst

    if packet.haslayer(ARP):
        layer = packet[ARP]
        return layer.psrc, layer.pdst

    return "N/A", "N/A"


def get_ports(packet):
    """Return TCP/UDP ports when available."""
    if packet.haslayer(TCP):
        layer = packet[TCP]
        return layer.sport, layer.dport

    if packet.haslayer(UDP):
        layer = packet[UDP]
        return layer.sport, layer.dport

    return "-", "-"


def handle_packet(packet, args):
    """Process and display a captured packet."""
    global displayed_count

    captured_packets.append(packet)

    protocol = get_protocol(packet)
    src, dst = get_addresses(packet)
    sport, dport = get_ports(packet)

    # Apply display filters
    if args.protocol and protocol != args.protocol.upper():
        return

    if args.ip and args.ip not in (src, dst):
        return

    if args.port:
        ports = (str(sport), str(dport))
        if str(args.port) not in ports:
            return

    displayed_count += 1
    protocol_counts[protocol] += 1
    source_counts[src] += 1
    destination_counts[dst] += 1

    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).strftime("%H:%M:%S")

    size = len(packet)

    print(
        f"{timestamp:<10} "
        f"{protocol:<8} "
        f"{src}:{sport} -> {dst}:{dport} "
        f"Size={size} bytes",
        end="",
    )

    if packet.haslayer(TCP):
        print(f" Flags={packet[TCP].flags}", end="")

    print()


def print_interfaces():
    """List interfaces available to Scapy."""
    print("\nAvailable network interfaces:")
    for interface in get_if_list():
        print(f"  {interface}")


def print_statistics():
    """Display a summary of displayed packets."""
    print("\n" + "=" * 55)
    print("             CAPTURE STATISTICS")
    print("=" * 55)

    print(f"Packets captured: {len(captured_packets)}")
    print(f"Packets displayed: {displayed_count}")

    print("\nProtocols:")
    if protocol_counts:
        for protocol, count in protocol_counts.most_common():
            print(f"  {protocol:<10}: {count}")
    else:
        print("  No packets matched the display filters.")

    print("\nTop source addresses:")
    for address, count in source_counts.most_common(5):
        print(f"  {address:<40} {count}")

    print("\nTop destination addresses:")
    for address, count in destination_counts.most_common(5):
        print(f"  {address:<40} {count}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python Packet Sniffer"
    )

    parser.add_argument(
        "-i", "--iface",
        help="Network interface name"
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        help='BPF capture filter, e.g. "tcp port 443"'
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after capturing this many packets; 0 means unlimited"
    )
    parser.add_argument(
        "-p", "--protocol",
        choices=["TCP", "UDP", "ICMP", "DNS", "ARP", "IP", "IPv6", "OTHER"],
        help="Display only this protocol"
    )
    parser.add_argument(
        "--ip",
        help="Display packets involving this exact IP address"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Display TCP/UDP packets involving this port"
    )
    parser.add_argument(
        "-o", "--output",
        default="captures/capture.pcap",
        help="PCAP output path"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit"
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count cannot be negative")

    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if args.list_interfaces:
        print_interfaces()
        return

    print("=" * 65)
    print("                 ADVANCED PACKET SNIFFER")
    print("=" * 65)
    print(f"Interface: {args.iface or 'Scapy default'}")
    print(f"BPF filter: {args.filter or 'None'}")
    print(f"Packet limit: {args.count or 'Unlimited'}")
    print("Press Ctrl+C to stop capturing.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=lambda pkt: handle_packet(pkt, args),
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as exc:
        print(f"\nCapture error: {exc}")
        print(
            "Check Npcap, administrator permissions, "
            "interface name, and BPF filter syntax."
        )
        return

    if captured_packets:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            wrpcap(str(output_path), captured_packets)
            print(f"\nPCAP saved to: {output_path.resolve()}")
        except Exception as exc:
            print(f"\nFailed to save PCAP: {exc}")

    print_statistics()


if __name__ == "__main__":
    main()
