
"""NetSentry desktop packet sniffer with live analytics and security alerts."""

import sys
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

import pyqtgraph as pg
from scapy.all import get_if_list

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QTabWidget,
)

from netsentry.capture_worker import CaptureWorker


BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURE_DIR = BASE_DIR / "captures"

DASHBOARD_PROTOCOLS = ["TCP", "UDP", "DNS", "ICMP", "Other"]


class NetSentryWindow(QMainWindow):
    MAX_ROWS = 1000
    MAX_ALERT_ROWS = 500
    HISTORY_SECONDS = 60

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetSentry - Network Packet Analyzer")
        self.resize(1400, 950)

        self.worker = None
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.total_alerts = 0

        self._last_rate_count = 0
        self._last_rate_time = time.monotonic()
        self._pps_history = deque(
            [0.0] * self.HISTORY_SECONDS,
            maxlen=self.HISTORY_SECONDS,
        )
        self._elapsed_seconds = 0

        self.setup_ui()
        self.load_interfaces()
        self.apply_styles()

        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.setInterval(1000)
        self.dashboard_timer.timeout.connect(self.update_pps_graph)
        self.dashboard_timer.start()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)

        title = QLabel("NetSentry")
        title.setObjectName("title")

        subtitle = QLabel(
            "REAL-TIME NETWORK MONITORING  |  TRAFFIC ANALYTICS"
        )
        subtitle.setObjectName("subtitle")

        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        # Capture controls
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Interface:"))

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(250)
        controls_layout.addWidget(self.interface_combo, 2)

        controls_layout.addWidget(QLabel("BPF Filter:"))

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "Optional: tcp, udp, port 53, host 192.168.1.1"
        )
        controls_layout.addWidget(self.filter_input, 3)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.load_interfaces)
        controls_layout.addWidget(self.refresh_button)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        controls_layout.addWidget(self.stop_button)

        main_layout.addLayout(controls_layout)

        self.status_label = QLabel("Status: Ready")
        self.status_label.setObjectName("status")
        main_layout.addWidget(self.status_label)

        # Dashboard statistic cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.packet_value = self.create_stat_card(
            cards_layout, "TOTAL PACKETS", "0"
        )
        self.bytes_value = self.create_stat_card(
            cards_layout, "TRAFFIC VOLUME", "0 B"
        )
        self.pps_value = self.create_stat_card(
            cards_layout, "PACKETS / SEC", "0"
        )
        self.protocol_value = self.create_stat_card(
            cards_layout, "PROTOCOLS SEEN", "0"
        )

        main_layout.addLayout(cards_layout)

        # Dashboard charts
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(12)

        rate_panel = QFrame()
        rate_panel.setObjectName("panel")
        rate_layout = QVBoxLayout(rate_panel)

        rate_title = QLabel("Live Packet Rate")
        rate_title.setObjectName("panelTitle")
        rate_layout.addWidget(rate_title)

        self.pps_plot = pg.PlotWidget()
        self.pps_plot.setBackground("#0f172a")
        self.pps_plot.showGrid(x=True, y=True, alpha=0.2)
        self.pps_plot.setLabel("left", "Packets / second")
        self.pps_plot.setLabel("bottom", "Time", units="seconds")
        self.pps_plot.setYRange(0, 10, padding=0.1)
        self.pps_plot.setMinimumHeight(210)

        self.pps_curve = self.pps_plot.plot(
            list(range(self.HISTORY_SECONDS)),
            list(self._pps_history),
            pen=pg.mkPen("#38bdf8", width=2),
        )
        rate_layout.addWidget(self.pps_plot)

        protocol_panel = QFrame()
        protocol_panel.setObjectName("panel")
        protocol_layout = QVBoxLayout(protocol_panel)

        protocol_title = QLabel("Protocol Distribution")
        protocol_title.setObjectName("panelTitle")
        protocol_layout.addWidget(protocol_title)

        self.protocol_plot = pg.PlotWidget()
        self.protocol_plot.setBackground("#0f172a")
        self.protocol_plot.showGrid(x=True, y=True, alpha=0.2)
        self.protocol_plot.setLabel("left", "Packets")
        self.protocol_plot.setMinimumHeight(210)
        self.protocol_plot.setMenuEnabled(False)
        self.protocol_plot.setMouseEnabled(x=False, y=False)
        self.protocol_plot.setXRange(-0.5, 4.5, padding=0)
        self.protocol_plot.getAxis("bottom").setTicks([
            [(i, name) for i, name in enumerate(DASHBOARD_PROTOCOLS)]
        ])

        self.protocol_bars = pg.BarGraphItem(
            x=list(range(len(DASHBOARD_PROTOCOLS))),
            height=[0] * len(DASHBOARD_PROTOCOLS),
            width=0.6,
            brush="#34d399",
        )
        self.protocol_plot.addItem(self.protocol_bars)
        protocol_layout.addWidget(self.protocol_plot)

        charts_layout.addWidget(rate_panel, 1)
        charts_layout.addWidget(protocol_panel, 1)
        main_layout.addLayout(charts_layout)

        # Tabs keep the packet feed and security alerts organized.
        self.tabs = QTabWidget()

        # Packet feed tab
        packet_tab = QWidget()
        packet_layout = QVBoxLayout(packet_tab)
        packet_layout.setContentsMargins(4, 8, 4, 4)

        packet_title = QLabel("Live Packet Feed")
        packet_title.setObjectName("panelTitle")
        packet_layout.addWidget(packet_title)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Time",
            "Protocol",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Size",
            "TCP Flags",
        ])
        self.configure_table(self.table)
        packet_layout.addWidget(self.table)

        self.tabs.addTab(packet_tab, "Packet Feed")

        # Security alerts tab
        alert_tab = QWidget()
        alert_layout = QVBoxLayout(alert_tab)
        alert_layout.setContentsMargins(4, 8, 4, 4)

        alert_controls = QHBoxLayout()

        alert_heading = QLabel("Security Alerts")
        alert_heading.setObjectName("panelTitle")
        alert_controls.addWidget(alert_heading)

        self.alert_counter = QLabel("Alerts: 0")
        self.alert_counter.setObjectName("status")
        alert_controls.addWidget(self.alert_counter)

        alert_controls.addStretch()

        self.clear_alerts_button = QPushButton("Clear Alerts")
        self.clear_alerts_button.clicked.connect(self.clear_alerts)
        alert_controls.addWidget(self.clear_alerts_button)

        alert_layout.addLayout(alert_controls)

        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(7)
        self.alert_table.setHorizontalHeaderLabels([
            "Timestamp",
            "Severity",
            "Detection Type",
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Reason",
        ])
        self.configure_table(self.alert_table)
        self.alert_table.setColumnWidth(0, 150)
        self.alert_table.setColumnWidth(1, 90)
        self.alert_table.setColumnWidth(2, 190)
        self.alert_table.setColumnWidth(3, 130)
        self.alert_table.setColumnWidth(4, 130)
        self.alert_table.setColumnWidth(5, 110)
        self.alert_table.horizontalHeader().setSectionResizeMode(
            6, QHeaderView.ResizeMode.Stretch
        )

        alert_layout.addWidget(self.alert_table)
        self.tabs.addTab(alert_tab, "Security Alerts (Heuristic)")

        main_layout.addWidget(self.tabs, 1)

        footer = QLabel(
            "NetSentry | Scapy-powered packet capture | "
            "PCAP files are saved in the captures folder"
        )
        footer.setObjectName("footer")
        main_layout.addWidget(footer)

    @staticmethod
    def configure_table(table):
        """Apply shared table settings."""
        table.setAlternatingRowColors(True)
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        table.horizontalHeader().setStretchLastSection(True)

    def create_stat_card(self, parent_layout, title, initial_value):
        card = QFrame()
        card.setObjectName("statCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)

        title_label = QLabel(title)
        title_label.setObjectName("statTitle")

        value_label = QLabel(initial_value)
        value_label.setObjectName("statValue")

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        parent_layout.addWidget(card, 1)
        return value_label

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #111827;
                color: #e5e7eb;
                font-family: Segoe UI;
                font-size: 10pt;
            }

            QLabel#title {
                font-size: 26pt;
                font-weight: bold;
                color: #60a5fa;
            }

            QLabel#subtitle {
                font-size: 10pt;
                color: #9ca3af;
                padding-bottom: 5px;
            }

            QLabel#status {
                color: #93c5fd;
                padding: 4px;
            }

            QFrame#statCard, QFrame#panel {
                background-color: #172033;
                border: 1px solid #374151;
                border-radius: 7px;
            }

            QLabel#statTitle {
                color: #9ca3af;
                font-size: 9pt;
                font-weight: bold;
            }

            QLabel#statValue {
                color: #60a5fa;
                font-size: 19pt;
                font-weight: bold;
            }

            QLabel#panelTitle {
                color: #f9fafb;
                font-size: 12pt;
                font-weight: bold;
                padding: 4px;
            }

            QLabel#footer {
                color: #9ca3af;
                padding-top: 4px;
            }

            QComboBox, QLineEdit {
                background-color: #1f2937;
                color: #f9fafb;
                border: 1px solid #374151;
                border-radius: 5px;
                padding: 7px;
            }

            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 12px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #1d4ed8;
            }

            QPushButton:disabled {
                background-color: #374151;
                color: #9ca3af;
            }

            QTabWidget::pane {
                border: 1px solid #374151;
                background-color: #111827;
            }

            QTabBar::tab {
                background-color: #1f2937;
                color: #cbd5e1;
                padding: 9px 16px;
                margin-right: 3px;
            }

            QTabBar::tab:selected {
                background-color: #2563eb;
                color: white;
            }

            QTableWidget {
                background-color: #0f172a;
                alternate-background-color: #172033;
                color: #e5e7eb;
                gridline-color: #374151;
                border: 1px solid #374151;
                selection-background-color: #1d4ed8;
            }

            QHeaderView::section {
                background-color: #1f2937;
                color: #f9fafb;
                padding: 8px;
                border: 1px solid #374151;
                font-weight: bold;
            }
        """)

    def load_interfaces(self):
        """Refresh available network interfaces."""
        current_interface = self.interface_combo.currentData()
        self.interface_combo.clear()

        try:
            interfaces = get_if_list()

            for interface in interfaces:
                self.interface_combo.addItem(interface, interface)

            if current_interface:
                index = self.interface_combo.findData(current_interface)
                if index >= 0:
                    self.interface_combo.setCurrentIndex(index)

            if not interfaces:
                self.status_label.setText(
                    "Status: No network interfaces found"
                )
            else:
                self.status_label.setText(
                    f"Status: {len(interfaces)} interfaces available"
                )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Interface Error",
                f"Could not load network interfaces:\n{exc}",
            )

    def reset_dashboard(self):
        """Reset dashboard and detection display for a new capture."""
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts.clear()
        self.total_alerts = 0

        self._last_rate_count = 0
        self._last_rate_time = time.monotonic()
        self._elapsed_seconds = 0
        self._pps_history = deque(
            [0.0] * self.HISTORY_SECONDS,
            maxlen=self.HISTORY_SECONDS,
        )

        self.packet_value.setText("0")
        self.bytes_value.setText("0 B")
        self.pps_value.setText("0")
        self.protocol_value.setText("0")
        self.alert_counter.setText("Alerts: 0")

        self.alert_table.setRowCount(0)

        self.pps_curve.setData(
            list(range(self.HISTORY_SECONDS)),
            list(self._pps_history),
        )
        self.protocol_bars.setOpts(
            height=[0] * len(DASHBOARD_PROTOCOLS)
        )

    def start_capture(self):
        """Start packet capture in the background."""
        if self.worker is not None and self.worker.isRunning():
            return

        interface = self.interface_combo.currentData()

        if not interface:
            QMessageBox.warning(
                self,
                "No Interface",
                "Select a network interface before starting capture.",
            )
            return

        bpf_filter = self.filter_input.text().strip()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = CAPTURE_DIR / f"capture_{timestamp}.pcap"

        self.table.setRowCount(0)
        self.reset_dashboard()
        self.status_label.setText("Status: Starting capture...")

        self.worker = CaptureWorker(
            interface=interface,
            bpf_filter=bpf_filter,
            output_path=str(output_path),
        )

        self.worker.packets_received.connect(self.add_packets)
        self.worker.count_updated.connect(self.update_count)
        self.worker.traffic_stats_updated.connect(
            self.update_traffic_stats
        )
        self.worker.alerts_received.connect(self.add_alerts)
        self.worker.capture_finished.connect(self.capture_finished)
        self.worker.capture_error.connect(self.capture_error)

        self.worker.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.refresh_button.setEnabled(False)
        self.interface_combo.setEnabled(False)
        self.filter_input.setEnabled(False)

        self.status_label.setText(
            f"Status: Capturing on {interface}"
        )

    def stop_capture(self):
        """Request the current capture to stop."""
        if self.worker is not None and self.worker.isRunning():
            self.status_label.setText("Status: Stopping capture...")
            self.stop_button.setEnabled(False)
            self.worker.request_stop()

    def add_packets(self, packets):
        """Append a batch to the visible packet table."""
        self.table.setUpdatesEnabled(False)

        try:
            for packet in packets:
                if self.table.rowCount() >= self.MAX_ROWS:
                    self.table.removeRow(0)

                row_index = self.table.rowCount()
                self.table.insertRow(row_index)

                values = [
                    packet["timestamp"],
                    packet["protocol"],
                    packet["src"],
                    packet["sport"],
                    packet["dst"],
                    packet["dport"],
                    str(packet["size"]),
                    packet["flags"],
                ]

                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))

                    if column in (3, 5, 6):
                        item.setTextAlignment(
                            Qt.AlignmentFlag.AlignRight
                            | Qt.AlignmentFlag.AlignVCenter
                        )

                    self.table.setItem(row_index, column, item)

        finally:
            self.table.setUpdatesEnabled(True)

        self.table.scrollToBottom()

    def add_alerts(self, alerts):
        """Display heuristic alerts received from the worker."""
        self.alert_table.setUpdatesEnabled(False)

        try:
            for alert in alerts:
                if self.alert_table.rowCount() >= self.MAX_ALERT_ROWS:
                    self.alert_table.removeRow(0)

                row_index = self.alert_table.rowCount()
                self.alert_table.insertRow(row_index)

                values = [
                    alert.get("timestamp", ""),
                    alert.get("severity", "Medium"),
                    alert.get("type", "Traffic heuristic"),
                    alert.get("source_ip", ""),
                    alert.get("destination_ip", ""),
                    str(alert.get("destination_port") or ""),
                    alert.get("reason", ""),
                ]

                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))

                    if column == 1:
                        if value == "High":
                            item.setForeground(Qt.GlobalColor.red)
                        elif value == "Medium":
                            item.setForeground(Qt.GlobalColor.yellow)

                    self.alert_table.setItem(row_index, column, item)

                self.total_alerts += 1

        finally:
            self.alert_table.setUpdatesEnabled(True)

        self.alert_counter.setText(f"Alerts: {self.total_alerts}")

        if alerts:
            self.tabs.setTabText(
                1, f"Security Alerts ({self.total_alerts})"
            )

    def clear_alerts(self):
        """Clear displayed alerts without stopping detection."""
        self.alert_table.setRowCount(0)
        self.total_alerts = 0
        self.alert_counter.setText("Alerts: 0")
        self.tabs.setTabText(1, "Security Alerts (Heuristic)")

    def update_count(self, count):
        """Update the packet count."""
        self.total_packets = count
        self.packet_value.setText(f"{count:,}")

    @staticmethod
    def format_bytes(total_bytes):
        if total_bytes < 1024:
            return f"{total_bytes:,} B"
        if total_bytes < 1024 ** 2:
            return f"{total_bytes / 1024:.1f} KB"
        if total_bytes < 1024 ** 3:
            return f"{total_bytes / (1024 ** 2):.2f} MB"
        return f"{total_bytes / (1024 ** 3):.2f} GB"

    @staticmethod
    def dashboard_protocol(protocol):
        name = str(protocol).upper()

        if "DNS" in name:
            return "DNS"
        if name == "TCP" or name.startswith("TCP/"):
            return "TCP"
        if name == "UDP" or name.startswith("UDP/"):
            return "UDP"
        if "ICMP" in name:
            return "ICMP"

        return "Other"

    def update_traffic_stats(self, count, total_bytes, protocol_counts):
        """Update summary cards and protocol chart."""
        self.total_packets = count
        self.total_bytes = total_bytes
        self.protocol_counts = Counter(protocol_counts)

        self.packet_value.setText(f"{count:,}")
        self.bytes_value.setText(self.format_bytes(total_bytes))

        categories = Counter()

        for protocol, protocol_count in self.protocol_counts.items():
            categories[self.dashboard_protocol(protocol)] += protocol_count

        self.protocol_value.setText(
            str(sum(value > 0 for value in categories.values()))
        )

        self.protocol_bars.setOpts(
            height=[
                categories.get(name, 0)
                for name in DASHBOARD_PROTOCOLS
            ]
        )

    def update_pps_graph(self):
        """Refresh the packet-rate graph once per second."""
        now = time.monotonic()
        elapsed = now - self._last_rate_time

        if elapsed <= 0:
            return

        packet_delta = self.total_packets - self._last_rate_count
        packets_per_second = max(0.0, packet_delta / elapsed)

        self._last_rate_count = self.total_packets
        self._last_rate_time = now

        self._pps_history.append(packets_per_second)
        self._elapsed_seconds += 1

        x_values = list(
            range(
                self._elapsed_seconds - self.HISTORY_SECONDS + 1,
                self._elapsed_seconds + 1,
            )
        )

        self.pps_curve.setData(x_values, list(self._pps_history))
        self.pps_value.setText(f"{packets_per_second:,.1f}")

        maximum = max(self._pps_history, default=0.0)
        self.pps_plot.setYRange(0, max(10, maximum * 1.2), padding=0.05)

    def capture_finished(self, message):
        """Handle a normally completed capture."""
        self.finish_capture_ui()
        self.status_label.setText("Status: Capture stopped")
        QMessageBox.information(self, "Capture Finished", message)

    def capture_error(self, message):
        """Display a capture error."""
        self.status_label.setText("Status: Capture error")
        QMessageBox.critical(self, "Capture Error", message)

        if self.worker is None or not self.worker.isRunning():
            self.finish_capture_ui()

    def finish_capture_ui(self):
        """Restore controls after capture stops."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_button.setEnabled(True)
        self.interface_combo.setEnabled(True)
        self.filter_input.setEnabled(True)

    def closeEvent(self, event):
        """Stop capture before closing the application."""
        if self.worker is not None and self.worker.isRunning():
            self.worker.request_stop()

            if not self.worker.wait(5000):
                QMessageBox.warning(
                    self,
                    "Capture Still Stopping",
                    "The capture is still stopping. Please try closing "
                    "the application again in a moment.",
                )
                event.ignore()
                return

        event.accept()


def main():
    app = QApplication(sys.argv)
    window = NetSentryWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
