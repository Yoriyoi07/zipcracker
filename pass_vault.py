import sqlite3
import os
import base64
import string
import secrets
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ==========================================
# CORE CRYPTOGRAPHY & DATABASE
# ==========================================
def generate_kdf_key(password, salt):
    """Derives a cryptographic key from a password and salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def init_db():
    conn = sqlite3.connect("multi_user_vault.db")
    cursor = conn.cursor()
    # Accounts Table: Stores the salt and the Vault Key (encrypted two different ways)
    cursor.execute('''CREATE TABLE IF NOT EXISTS accounts 
                      (id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, 
                       enc_vault_key_master BLOB, enc_vault_key_recovery BLOB)''')
    # Vault Table: Now linked to a specific account_id
    cursor.execute('''CREATE TABLE IF NOT EXISTS vault 
                      (id INTEGER PRIMARY KEY, account_id INTEGER, site TEXT, username TEXT, encrypted_password BLOB)''')
    conn.commit()
    return conn

# ==========================================
# THE APPLICATION
# ==========================================
class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Pro Local Vault")
        self.geometry("450x700")
        self.resizable(False, False)
        
        self.conn = init_db()
        self.cipher_suite = None      # The active Vault Key
        self.current_user_id = None   # Who is currently logged in
        self.timeout_id = None

        self.bind_all("<Any-KeyPress>", self.reset_timer)
        self.bind_all("<Any-Button>", self.reset_timer)

        self.build_login_screen()

    # --- UI: LOGIN SCREEN ---
    def build_login_screen(self):
        self.clear_window()
        self.lock_vault()
        
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(pady=80, padx=60, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Sign In", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 20))
        
        self.login_user = ctk.CTkEntry(frame, placeholder_text="Username", width=220)
        self.login_user.pack(pady=10)
        
        self.login_pass = ctk.CTkEntry(frame, placeholder_text="Master Password", show="*", width=220)
        self.login_pass.pack(pady=10)
        self.login_pass.bind('<Return>', lambda event: self.sign_in())
        
        ctk.CTkButton(frame, text="Sign In", command=self.sign_in, corner_radius=8).pack(pady=(20, 10))
        
        # Links
        ctk.CTkButton(frame, text="Create Account", command=self.build_register_screen, fg_color="transparent", hover_color="#333333").pack(pady=5)
        ctk.CTkButton(frame, text="Forgot Password?", command=self.build_recovery_screen, fg_color="transparent", text_color="#ffcc00", hover_color="#333333").pack(pady=5)

    # --- UI: CREATE ACCOUNT SCREEN ---
    def build_register_screen(self):
        self.clear_window()
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(pady=80, padx=60, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Create Account", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(30, 20))
        
        self.reg_user = ctk.CTkEntry(frame, placeholder_text="Choose Username", width=220)
        self.reg_user.pack(pady=10)
        self.reg_pass = ctk.CTkEntry(frame, placeholder_text="Create Master Password", show="*", width=220)
        self.reg_pass.pack(pady=10)
        
        ctk.CTkButton(frame, text="Register", command=self.register_account, fg_color="#28a745", hover_color="#218838").pack(pady=(20, 10))
        ctk.CTkButton(frame, text="Back to Login", command=self.build_login_screen, fg_color="transparent", hover_color="#333333").pack(pady=5)

    # --- UI: RECOVERY SCREEN ---
    def build_recovery_screen(self):
        self.clear_window()
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(pady=80, padx=60, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Account Recovery", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(30, 20))
        
        self.rec_user = ctk.CTkEntry(frame, placeholder_text="Username", width=220)
        self.rec_user.pack(pady=10)
        self.rec_code = ctk.CTkEntry(frame, placeholder_text="Recovery Code (XXXX-XXXX)", width=220)
        self.rec_code.pack(pady=10)
        self.new_pass = ctk.CTkEntry(frame, placeholder_text="New Master Password", show="*", width=220)
        self.new_pass.pack(pady=10)
        
        ctk.CTkButton(frame, text="Reset Password", command=self.recover_account, fg_color="#ffcc00", text_color="black", hover_color="#e6b800").pack(pady=(20, 10))
        ctk.CTkButton(frame, text="Back to Login", command=self.build_login_screen, fg_color="transparent", hover_color="#333333").pack(pady=5)

    # --- UI: VAULT SCREEN ---
    def build_vault_screen(self):
        self.clear_window()
        self.start_timer()
        
        # Header
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(10, 0))
        ctk.CTkLabel(header_frame, text="Vault Dashboard", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(header_frame, text="Log Out", width=80, command=self.build_login_screen, fg_color="#dc3545", hover_color="#c82333").pack(side="right")

        # Add Password Card
        add_frame = ctk.CTkFrame(self, corner_radius=10)
        add_frame.pack(pady=15, padx=20, fill="x")
        ctk.CTkLabel(add_frame, text="Add / Update Entry", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(10, 5))
        self.site_add = ctk.CTkEntry(add_frame, placeholder_text="Site Name (e.g. Netflix)", width=300)
        self.site_add.pack(pady=5)
        self.user_add = ctk.CTkEntry(add_frame, placeholder_text="Username / Email", width=300)
        self.user_add.pack(pady=5)
        self.pass_add = ctk.CTkEntry(add_frame, placeholder_text="Password", show="*", width=300)
        self.pass_add.pack(pady=5)
        
        btn_frame1 = ctk.CTkFrame(add_frame, fg_color="transparent")
        btn_frame1.pack(pady=(10, 15))
        ctk.CTkButton(btn_frame1, text="Generate", width=100, command=self.generate_pwd).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame1, text="Save to Vault", width=140, command=self.save_password, fg_color="#28a745").pack(side="left", padx=5)
        
        # Manage Vault Card
        get_frame = ctk.CTkFrame(self, corner_radius=10)
        get_frame.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(get_frame, text="Manage Vault", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(10, 5))
        self.site_search = ctk.CTkEntry(get_frame, placeholder_text="Exact Site Name", width=300)
        self.site_search.pack(pady=5)
        
        btn_frame2 = ctk.CTkFrame(get_frame, fg_color="transparent")
        btn_frame2.pack(pady=(10, 15))
        ctk.CTkButton(btn_frame2, text="Copy Password", width=140, command=self.get_password).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame2, text="Delete", width=100, command=self.delete_password, fg_color="#dc3545").pack(side="left", padx=5)

    # ==========================================
    # LOGIC: AUTHENTICATION & RECOVERY
    # ==========================================
    def register_account(self):
        user, pwd = self.reg_user.get(), self.reg_pass.get()
        if not user or not pwd:
            messagebox.showwarning("Error", "Fill all fields!")
            return

        cursor = self.conn.cursor()
        try:
            salt = os.urandom(16)
            
            # 1. Create the invisible Vault Key (The real encryption key)
            raw_vault_key = Fernet.generate_key() 
            
            # 2. Generate a random 12-character Recovery Code
            alphabet = string.ascii_uppercase + string.digits
            recovery_code = '-'.join([''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)])
            
            # 3. Create 'padlocks' (KEKs) from the Master Pwd and the Recovery Code
            master_kek = generate_kdf_key(pwd, salt)
            recovery_kek = generate_kdf_key(recovery_code, salt)
            
            # 4. Lock the Vault Key inside both padlocks
            enc_vault_key_master = Fernet(master_kek).encrypt(raw_vault_key)
            enc_vault_key_recovery = Fernet(recovery_kek).encrypt(raw_vault_key)
            
            cursor.execute("INSERT INTO accounts (username, salt, enc_vault_key_master, enc_vault_key_recovery) VALUES (?, ?, ?, ?)", 
                           (user, salt, enc_vault_key_master, enc_vault_key_recovery))
            self.conn.commit()
            
            # 5. Show the user their one-time code
            msg = f"Account created successfully!\n\nYOUR EMERGENCY RECOVERY CODE:\n{recovery_code}\n\nWrite this down! It will only be shown ONCE."
            messagebox.showinfo("CRITICAL: Save Your Code", msg)
            self.build_login_screen()
            
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")

    def sign_in(self):
        user, pwd = self.login_user.get(), self.login_pass.get()
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, salt, enc_vault_key_master FROM accounts WHERE username = ?", (user,))
        account = cursor.fetchone()

        if account:
            acc_id, salt, enc_vault_key_master = account
            master_kek = generate_kdf_key(pwd, salt)
            try:
                # Try to unlock the Vault Key using the Master Pwd padlock
                raw_vault_key = Fernet(master_kek).decrypt(enc_vault_key_master)
                self.cipher_suite = Fernet(raw_vault_key) # Success! Load the engine.
                self.current_user_id = acc_id
                self.build_vault_screen()
            except InvalidToken:
                messagebox.showerror("Access Denied", "Incorrect Password.")
        else:
            messagebox.showerror("Access Denied", "User not found.")

    def recover_account(self):
        user, code, new_pwd = self.rec_user.get(), self.rec_code.get(), self.new_pass.get()
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, salt, enc_vault_key_recovery FROM accounts WHERE username = ?", (user,))
        account = cursor.fetchone()

        if account:
            acc_id, salt, enc_vault_key_recovery = account
            recovery_kek = generate_kdf_key(code.upper(), salt)
            try:
                # 1. Unlock the Vault Key using the OLD Recovery Code padlock
                raw_vault_key = Fernet(recovery_kek).decrypt(enc_vault_key_recovery)
                
                # 2. Create a NEW padlock using the NEW Master Password
                new_master_kek = generate_kdf_key(new_pwd, salt)
                new_enc_vault_key_master = Fernet(new_master_kek).encrypt(raw_vault_key)
                
                # 3. THE FIX: Generate a brand NEW Recovery Code and padlock
                alphabet = string.ascii_uppercase + string.digits
                new_recovery_code = '-'.join([''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)])
                new_recovery_kek = generate_kdf_key(new_recovery_code, salt)
                new_enc_vault_key_recovery = Fernet(new_recovery_kek).encrypt(raw_vault_key)
                
                # 4. Update the database with BOTH new padlocks (killing the old ones)
                cursor.execute("""UPDATE accounts 
                                  SET enc_vault_key_master = ?, enc_vault_key_recovery = ? 
                                  WHERE id = ?""", 
                               (new_enc_vault_key_master, new_enc_vault_key_recovery, acc_id))
                self.conn.commit()
                
                # 5. Give the user their new code
                msg = f"Password reset successfully!\n\nYOUR NEW RECOVERY CODE:\n{new_recovery_code}\n\nThe old code is now dead. Save this new one!"
                messagebox.showinfo("Success", msg)
                self.build_login_screen()
                
            except InvalidToken:
                messagebox.showerror("Access Denied", "Invalid Recovery Code.")
        else:
            messagebox.showerror("Access Denied", "User not found.")

    # ==========================================
    # LOGIC: VAULT OPERATIONS (Bound to current_user_id)
    # ==========================================
    def generate_pwd(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.pass_add.delete(0, tk.END)
        self.pass_add.insert(0, pwd)

    def save_password(self):
        site, user, pwd = self.site_add.get(), self.user_add.get(), self.pass_add.get()
        if not (site and user and pwd): return messagebox.showwarning("Error", "Fill all fields!")
            
        enc_pwd = self.cipher_suite.encrypt(pwd.encode())
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM vault WHERE site = ? AND username = ? AND account_id = ?", (site, user, self.current_user_id))
        existing = cursor.fetchone()
        
        if existing:
            if messagebox.askyesno("Update", f"Update password for {site}?"):
                cursor.execute("UPDATE vault SET encrypted_password = ? WHERE id = ?", (enc_pwd, existing[0]))
        else:
            cursor.execute("INSERT INTO vault (account_id, site, username, encrypted_password) VALUES (?, ?, ?, ?)", 
                           (self.current_user_id, site, user, enc_pwd))
        
        self.conn.commit()
        messagebox.showinfo("Success", "Saved securely!")
        self.site_add.delete(0, tk.END); self.user_add.delete(0, tk.END); self.pass_add.delete(0, tk.END)

    def get_password(self):
        search = self.site_search.get()
        cursor = self.conn.cursor()
        cursor.execute("SELECT username, encrypted_password FROM vault WHERE site = ? AND account_id = ?", (search, self.current_user_id))
        result = cursor.fetchone()

        if result:
            decrypted_pwd = self.cipher_suite.decrypt(result[1]).decode()
            self.clipboard_clear(); self.clipboard_append(decrypted_pwd); self.update() 
            messagebox.showinfo("Success", f"User: {result[0]}\n\nPassword copied!\nWill clear in 10s.")
            self.after(10000, self.clear_clipboard)
        else:
            messagebox.showinfo("Not Found", "No match found in your vault.")

    def delete_password(self):
        search = self.site_search.get()
        cursor = self.conn.cursor()
        cursor.execute("SELECT username FROM vault WHERE site = ? AND account_id = ?", (search, self.current_user_id))
        if cursor.fetchone():
            if messagebox.askyesno("Confirm", f"PERMANENTLY delete '{search}'?"):
                cursor.execute("DELETE FROM vault WHERE site = ? AND account_id = ?", (search, self.current_user_id))
                self.conn.commit()
                messagebox.showinfo("Deleted", f"Entry erased.")
                self.site_search.delete(0, tk.END)
        else:
            messagebox.showinfo("Not Found", "No match found.")

    # ==========================================
    # UTILITY
    # ==========================================
    def lock_vault(self):
        """Wipes the keys from memory when logged out or timed out."""
        self.cipher_suite = None
        self.current_user_id = None
        if self.timeout_id: self.after_cancel(self.timeout_id)

    def start_timer(self):
        self.timeout_id = self.after(300000, self.auto_lock)

    def reset_timer(self, event=None):
        if self.cipher_suite and self.timeout_id:
            self.after_cancel(self.timeout_id)
            self.start_timer()

    def auto_lock(self):
        self.build_login_screen()
        messagebox.showinfo("Locked", "Vault automatically locked due to 5 minutes of inactivity.")

    def clear_clipboard(self):
        self.clipboard_clear(); self.clipboard_append(""); self.update()

    def clear_window(self):
        for widget in self.winfo_children(): widget.destroy()

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()