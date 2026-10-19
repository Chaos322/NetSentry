
"""Launch the NetSentry desktop application."""

import sys

from PySide6.QtWidgets import QApplication
from netsentry.gui import NetSentryWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NetSentry")
    app.setStyle("Fusion")

    window = NetSentryWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
