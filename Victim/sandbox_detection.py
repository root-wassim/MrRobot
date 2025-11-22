
import ctypes
import psutil
import time
import random
from ctypes import wintypes
import sys


def detect_vm_memory():
    memory = psutil.virtual_memory()
    
    if memory.total < 2 * 1024 * 1024 * 1024:  
        return True
    return False


def detect_vm_cpu():
    cpu_count = psutil.cpu_count()
    if cpu_count < 2:  
        return True
    return False


def detect_uptime():
    uptime = time.time() - psutil.boot_time()
    if uptime < 300:  
        return True
    return False


def detect_analysis_processes():
    analysis_processes = [
        "ollydbg.exe", "idaq.exe", "wireshark.exe", "procmon.exe",
        "processhacker.exe", "tcpview.exe", "regmon.exe", "filemon.exe",
        "vboxservice.exe", "vmwaretray.exe", "vboxtray.exe", "xenservice.exe",
        "procmon64.exe", "procexp.exe", "procexp64.exe", "autoruns.exe",
        "autorunsc.exe", "sysmon.exe", "sysmon64.exe", "cuckoo.exe",
        "joebox.exe", "sandboxie.exe", "fiddler.exe", "burpsuite.exe",
        "immunitydebugger.exe", "windbg.exe", "x64_dbg.exe"
    ]
    
    for process in psutil.process_iter(['name']):
        if process.info['name'].lower() in analysis_processes:
            return True
    return False


def detect_mouse_activity():
    try:
        user32 = ctypes.windll.user32
      
        last_input = wintypes.DWORD()
        user32.GetLastInputInfo(ctypes.byref(last_input))
        idle_time = (user32.GetTickCount() - last_input.value) / 1000.0
        
        if idle_time > 60:  
            return True
    except:
        pass
    return False


def detect_vm_mac():
    import uuid
    mac = uuid.getnode()
    mac_hex = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
    
    vm_mac_prefixes = [
        '00:05:69', '00:0C:29', '00:1C:14', '00:50:56',  # VMware
        '08:00:27',  # VirtualBox
        '00:15:5D'   # Hyper-V
    ]
    
    for prefix in vm_mac_prefixes:
        if mac_hex.startswith(prefix):
            return True
    return False


def detect_vm_windows():
    vm_windows = [
            "VBoxTrayToolWndClass",  # VirtualBox
            "VBoxTrayToolWnd",       # VirtualBox  
            "Vmusrvc",               # VMware
            "VMwareTray",            # VMware
            "VMwareUser",            # VMware
            "VBoxTray",              # VirtualBox
            "Vboxtray",              # VirtualBox
            "Vmtoolsd",              # VMware
        ]
    
    user32 = ctypes.windll.user32
    for window in vm_windows:
        if user32.FindWindowW(window, None):
            return True
    return False


def detect_vm_registry():
    
    try:
        import winreg
        
        vm_registry_keys = [
            ("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"),
            ("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0"),
            ("HARDWARE\\Description\\System", "SystemBiosVersion"),
            ("HARDWARE\\Description\\System", "VideoBiosVersion"),
        ]
        
        vm_indicators = [
            "vbox", "vmware", "virtual", "qemu", "xen", "hyper-v",
            "parallels", "virtualbox", "vmware", "innotek"
        ]
        
        for key_path, value_name in vm_registry_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if any(indicator in str(value).lower() for indicator in vm_indicators):
                        
                        return True
            except:
                continue
                
        return False
    except:
        return False

def detect_debugger():
   
    try:
        kernel32 = ctypes.windll.kernel32
        
        
        if kernel32.IsDebuggerPresent():
          
            return True
        
       
        remote_debugger = wintypes.BOOL()
        if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(remote_debugger)):
            if remote_debugger.value:
                
                return True
        
        return False
    except:
        return False

def detect_sandbox_files():
 
    sandbox_paths = [
        "C:\\analysis", "C:\\sandbox", "C:\\malware", "C:\\sample",
        "C:\\virus", "C:\\cuckoo", "C:\\joebox", "C:\\anubis",
        "C:\\fireeye", "C:\\threat", "C:\\debug", "C:\\temp\\avtest",
        "C:\\temp\\sandbox", "C:\\users\\sandbox", "C:\\users\\malware",
        "C:\\users\\analyst", "C:\\program files\\fiddler2",
        "C:\\program files\\wireshark", "C:\\program files\\ollydbg"
    ]
    
    for path in sandbox_paths:
        if os.path.exists(path):
          
            return True
    return False

def sleeping ():
    x = 0
    sleep_time = random.randint(300, 600)
    time.sleep(sleep_time)
    for i in range(100):
            x = random.randint(1, 1000)
            y = random.randint(1, 1000)
            result = x * y / (x + 1) if x != -1 else 0


def main():
    
    checks = [
        detect_vm_memory,
        detect_vm_cpu,
        detect_uptime,
        detect_analysis_processes,
        detect_mouse_activity,
        detect_vm_mac,
        detect_vm_windows,
        detect_vm_registry,
        detect_debugger,
        detect_sandbox_files
    ]
    
    max_attempts = 5
    attempt = 0
    
    while attempt < max_attempts:
        attempt += 1
        
       
        positive_checks = 0
        total_checks = len(checks)
        
        for detect_func in checks:
            try:
                if detect_func():
                    positive_checks += 1
            except Exception as e:
                pass
        
       
        if positive_checks >= 2:
          
            if attempt == max_attempts:
              
                sys.exit(0)
            
           
            sleeping()
        else:
           
            break
    