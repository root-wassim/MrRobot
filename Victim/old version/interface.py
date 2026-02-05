import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import random
import pygame

class MrRobotUI:
    def __init__(self, root):
        self.root = root
        self.root.title("fsociety - Project Mr. Robot")
        self.root.geometry("1024x640")
        self.root.resizable(False, False)
        
        pygame.mixer.init()
        self.play_bg_music()

        self.center_x = 0.795
        self.timer_y = 0.725
        self.btn_y = 0.86

        try:
            self.bg_image = Image.open("mrrobot2.png")
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            self.bg_label = tk.Label(root, image=self.bg_photo)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except:
            self.root.configure(bg="#050505")
            tk.Label(root, text="[IMG_NOT_FOUND: mrrobot2.png]", fg="red", bg="black").pack()

        self.warning_label = tk.Label(root, 
            text="NOTICE: IF THE TIMER EXPIRES WITHOUT PAYMENT, FILES WILL BE ENCRYPTED FOREVER.", 
            font=("Consolas", 11, "bold"), 
            fg="#ff0000", bg="#0a0a0a", 
            wraplength=350, justify="center")
        self.warning_label.place(relx=self.center_x, rely=0.62, anchor="center")

        self.time_left = 86400 
        self.timer_label = tk.Label(root, text="", font=("Courier", 42, "bold"), 
                                    fg="#ff0000", bg="#0a0a0a", bd=0)
        self.timer_label.place(relx=self.center_x, rely=self.timer_y, anchor="center")
        self.update_timer()

        self.glow_frame = tk.Frame(root, bg="#ff0000", padx=2, pady=2)
        self.glow_frame.place(relx=self.center_x, rely=self.btn_y, anchor="center")

        self.pay_btn = tk.Button(self.glow_frame, 
                                 text="  INITIALIZE PAYMENT  ", 
                                 command=self.pay_action,
                                 font=("Courier New", 14, "bold"),
                                 fg="#ff0000", bg="#1a0000",
                                 activeforeground="#ffffff", activebackground="#ff0000",
                                 relief="raised", 
                                 borderwidth=5,   
                                 cursor="hand2")
        self.pay_btn.pack()

        self.pay_btn.bind("<Enter>", self.on_enter)
        self.pay_btn.bind("<Leave>", self.on_leave)
        
        self.apply_glitch()

    def play_bg_music(self):
        try:
            pygame.mixer.music.load("mrrobot_sound.mp3")
            pygame.mixer.music.play(-1) 
        except Exception as e:
            print(f"Music Error: {e}")

    def on_enter(self, e):
        self.pay_btn.config(bg="#ff0000", fg="#ffffff")
        self.glow_frame.config(bg="#ffffff")

    def on_leave(self, e):
        self.pay_btn.config(bg="#1a0000", fg="#ff0000")
        self.glow_frame.config(bg="#ff0000")

    def update_timer(self):
        hours, remainder = divmod(self.time_left, 3600)
        mins, secs = divmod(remainder, 60)
        self.timer_label.config(text=f"{hours:02}:{mins:02}:{secs:02}")
        if self.time_left > 0:
            self.time_left -= 1
            self.root.after(1000, self.update_timer)

    def apply_glitch(self):
        if random.random() > 0.90:
            self.timer_label.place_configure(relx=self.center_x + random.uniform(-0.01, 0.01))
            self.pay_btn.config(fg="#ffffff")
        else:
            self.timer_label.place_configure(relx=self.center_x)
            if self.pay_btn['bg'] != "#ff0000":
                self.pay_btn.config(fg="#ff0000")
                
        self.root.after(random.randint(100, 500), self.apply_glitch)

    def pay_action(self):
        messagebox.showerror("CRITICAL", "HANDSHAKE_FAILED: SERVER_NOT_RESPONDING")

if __name__ == "__main__":
    root = tk.Tk()
    app = MrRobotUI(root)
    root.mainloop()