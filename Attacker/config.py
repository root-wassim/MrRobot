# config_server.py - Server Configuration
import os

# ==================== Server Settings ====================
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 1234
BUFFER_SIZE = 4096
MAX_CONNECTIONS = 10

# ==================== Key Management ====================
KEY_DIR = "keys"
KEY_SIZE = 4096

# ==================== Logging ====================
LOG_DIR = "logs"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# ==================== Network Settings ====================
RECONNECT_TIMEOUT = 60
HEARTBEAT_INTERVAL = 30

# ==================== Command Settings ====================
MAX_COMMAND_QUEUE = 100
COMMAND_TIMEOUT = 300  # 5 minutes

def ensure_directories():
    """Ensure required directories exist"""
    os.makedirs(KEY_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

# Initialize directories
ensure_directories()