
"""Memory-conscious packet capture worker for NetSentry."""

import threading
from datetime import datetime
from pathlib import Path

from scapy.all import AsyncSniffer, TCP, PcapWriter
from PySide6.QtCore import QThread, Signal

from main import get_protocol, get_addresses, get_ports
from netsentry.security_detector import SecurityDetector


class CaptureWorker(QThread):
    packets_received = Signal(list)
    count_updated = Signal(int)
    traffic_stats_updated = Signal(int, int, dict)
    alerts_received = Signal(list)
    capture_finished = Signal(str)
    capture_error = Signal(str)

    BATCH_SIZE = 50
    STATS_INTERVAL = 0.25

    def __init__(
        self,
        interface,
        bpf_filter=None,
        output_path="captures/capture.pcap",
        parent=None,
    ):
        super().__init__(parent)

        self.interface = interface
        self.bpf_filter = bpf_filter or None
        self.output_path = Path(output_path)

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._pending_rows = []
        self._packet_count = 0
        self._total_bytes = 0
        self._protocol_counts = {}
        self._writer = None
        self._sniffer = None

        self.detector = SecurityDetector()

    def request_stop(self):
        self._stop_event.set()

    def _process_packet(self, packet):
        """Save packets, update statistics, and evaluate detection rules."""
        try:
            with self._lock:
                if self._stop_event.is_set():
                    return

                if self._writer is not None:
                    self._writer.write(packet)

                self._packet_count += 1
                packet_size = len(packet)
                self._total_bytes += packet_size

                protocol = str(get_protocol(packet))
                self._protocol_counts[protocol] = (
                    self._protocol_counts.get(protocol, 0) + 1
                )

                src, dst = get_addresses(packet)
                sport, dport = get_ports(packet)

                flags = (
                    str(packet[TCP].flags)
                    if packet.haslayer(TCP)
                    else "-"
                )

                try:
                    timestamp = datetime.fromtimestamp(
                        float(packet.time)
                    ).strftime("%H:%M:%S.%f")[:-3]
                except (ValueError, TypeError, OSError, OverflowError):
                    timestamp = datetime.now().strftime(
                        "%H:%M:%S.%f"
                    )[:-3]

                row = {
                    "timestamp": timestamp,
                    "protocol": protocol,
                    "src": str(src),
                    "sport": str(sport),
                    "dst": str(dst),
                    "dport": str(dport),
                    "size": packet_size,
                    "flags": flags,
                }

                self._pending_rows.append(row)

                if len(self._pending_rows) >= self.BATCH_SIZE:
                    batch = self._pending_rows
                    self._pending_rows = []
                else:
                    batch = None

            # Run detection outside the capture-statistics lock.
            alerts = self.detector.analyze_packet(row)

            if alerts:
                self.alerts_received.emit(alerts)

            if batch:
                self.packets_received.emit(batch)

        except Exception as exc:
            self.capture_error.emit(
                f"Packet processing failed: {exc}"
            )
            self.request_stop()

    def _flush_pending(self):
        """Publish pending packet rows and statistics snapshots."""
        with self._lock:
            batch = self._pending_rows
            self._pending_rows = []

            count = self._packet_count
            total_bytes = self._total_bytes
            protocol_counts = dict(self._protocol_counts)

        if batch:
            self.packets_received.emit(batch)

        self.count_updated.emit(count)
        self.traffic_stats_updated.emit(
            count,
            total_bytes,
            protocol_counts,
        )

    def run(self):
        """Capture packets and close the PCAP writer cleanly."""
        error_message = None

        try:
            self.output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self._writer = PcapWriter(
                str(self.output_path),
                append=False,
                sync=False,
            )

            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
            )

            self._sniffer.start()

            while not self._stop_event.wait(self.STATS_INTERVAL):
                if not self._sniffer.running:
                    break

                self._flush_pending()

            if self._sniffer.running:
                self._sniffer.stop(join=True)

        except Exception as exc:
            error_message = str(exc)

        finally:
            try:
                if self._sniffer is not None:
                    if self._sniffer.running:
                        self._sniffer.stop(join=True)
            except Exception as exc:
                if error_message is None:
                    error_message = str(exc)

            try:
                if self._writer is not None:
                    self._writer.close()
            except Exception as exc:
                if error_message is None:
                    error_message = f"PCAP close failed: {exc}"

            self._writer = None
            self._sniffer = None

            self._flush_pending()

        if error_message:
            self.capture_error.emit(error_message)
        else:
            self.capture_finished.emit(
                f"Capture stopped. {self._packet_count} packets saved to "
                f"{self.output_path.resolve()}"
            )
