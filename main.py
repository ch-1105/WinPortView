"""Port Viewer — Windows 端口查看器

A lightweight GUI tool to view active TCP/UDP ports, their owning
processes, and associated Windows services on localhost.
"""

from main_window import MainWindow


def main():
    app = MainWindow()
    app.run()


if __name__ == "__main__":
    main()
