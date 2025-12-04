import os
import subprocess
import secrets

def build_malware():
    victim_dir = "victim"
    if not os.path.exists(victim_dir):
        os.makedirs(victim_dir)
        print(f"Created {victim_dir}/ - add your malware files there")
        return
    



    key = secrets.token_hex(16)
    
    cmd = [
        "pyinstaller",
        "--onefile",
        "--noconsole",
        f"--key={key}",
        "--clean",
        "--upx",
        os.path.join(victim_dir, "main.py")
    ]
    


    print(f"Building with encryption key: {key}")
    subprocess.run(cmd)
    
    exe_path = "dist/main.exe"
    if os.path.exists(exe_path):
        print(f"Executable created: {exe_path}")
        print(f"Key for execution: {key}")





#root-wassim 
