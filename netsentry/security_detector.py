
"""Rule-based defensive traffic detection for NetSentry."""

from collections import defaultdict, deque
from time import monotonic
from datetime import datetime


class SecurityDetector:
    """Detect basic suspicious traffic patterns using configurable rules."""

    def __init__(
        self,
        syn_threshold=10,
        detection_window=10,
        alert_cooldown=60,
        watched_ports=None,
    ):
        self.syn_threshold = syn_threshold
        self.detection_window = detection_window
        self.alert_cooldown = alert_cooldown

        # These ports are configurable examples, not proof of malicious use.
        self.watched_ports = set(
            watched_ports
            if watched_ports is not None
            else {23, 2323, 4444, 5555, 31337}
        )

        self._syn_attempts = defaultdict(deque)
        self._last_alert = {}

    def reset(self):
        """Clear tracking state for a new capture session."""
        self._syn_attempts.clear()
        self._last_alert.clear()

    def _make_alert(
        self,
        alert_type,
        source_ip,
        destination_ip,
        destination_port,
        reason,
        severity="Medium",
    ):
        """Create an alert unless an equivalent alert is in cooldown."""
        now = monotonic()

        key = (
            alert_type,
            source_ip,
            destination_ip,
            destination_port,
        )

        last_time = self._last_alert.get(key)

        if (
            last_time is not None
            and now - last_time < self.alert_cooldown
        ):
            return None

        self._last_alert[key] = now

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "reason": reason,
        }

    def analyze_packet(self, packet):
        """Analyze one packet summary and return zero or more alerts."""
        alerts = []

        source_ip = str(packet.get("src", "Unknown"))
        destination_ip = str(packet.get("dst", "Unknown"))
        protocol = str(packet.get("protocol", "")).upper()
        flags = str(packet.get("flags", ""))
        destination_port = self._parse_port(packet.get("dport"))

        # Rule 1: repeated TCP SYN attempts from one source IP.
        # A SYN flag without ACK is treated as a new connection attempt.
        is_initial_syn = (
            protocol == "TCP"
            and "S" in flags
            and "A" not in flags
        )

        if is_initial_syn and source_ip != "Unknown":
            now = monotonic()
            attempts = self._syn_attempts[source_ip]
            attempts.append(now)

            cutoff = now - self.detection_window

            while attempts and attempts[0] < cutoff:
                attempts.popleft()

            if len(attempts) >= self.syn_threshold:
                alert = self._make_alert(
                    alert_type="Repeated TCP SYN attempts",
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    reason=(
                        f"{len(attempts)} initial TCP SYN packets from "
                        f"this source within {self.detection_window} seconds"
                    ),
                    severity="High",
                )

                if alert is not None:
                    alerts.append(alert)

        # Rule 2: traffic directed to a watched destination port.
        if (
            destination_port is not None
            and destination_port in self.watched_ports
        ):
            alert = self._make_alert(
                alert_type="Watched destination port",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                reason=(
                    f"Traffic observed to watched destination port "
                    f"{destination_port}"
                ),
                severity="Medium",
            )

            if alert is not None:
                alerts.append(alert)

        return alerts

    @staticmethod
    def _parse_port(value):
        """Convert a port value to an integer when possible."""
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None

        if 0 <= port <= 65535:
            return port

        return None
