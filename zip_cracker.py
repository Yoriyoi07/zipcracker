"""
PROJECT: CyberScan - Zip Cracker Pro (v3.1)
FEATURES: File Browser, Default Wordlist, Strength Meter, and Detailed Export.
"""

import zipfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
import re
import os 

# DEFAULT PASSWORD LIST
DEFAULT_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "12345", "123456789",
    "football", "dragon", "admin", "admin123", "welcome", "secret",
    "password123", "p@ssword", "monkey", "charlie", "letmein", "sunshine"
]

def check_strength(password):
    strength = 0
    if len(password) >= 8: strength += 1
    if re.search("[a-z]", password) and re.search("[A-Z]", password): strength += 1
    if re.search("[0-9]", password): strength += 1
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password): strength += 1
    
    levels = {0: ("Weak", "red"), 1: ("Weak", "red"), 2: ("Fair", "orange"), 
              3: ("Good", "blue"), 4: ("Strong", "green")}
    return levels.get(strength)

def browse_zip():
    filename = filedialog.askopenfilename(title="Select ZIP", filetypes=[("ZIP files", "*.zip")])
    if filename:
        zip_entry.delete(0, tk.END)
        zip_entry.insert(0, filename)

def browse_wordlist():
    filename = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text files", "*.txt")])
    if filename:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(0, filename)

def save_log():
    """Exports the results box with the target filename included."""
    content = result_display.get(1.0, tk.END)
    zip_path = zip_entry.get()
    
    # Extract just the filename (e.g., 'protected.zip') from the full path
    zip_name = os.path.basename(zip_path) if zip_path else "Unknown File"

    if len(content.strip()) < 10:
        messagebox.showwarning("Warning", "No data to save!")
        return
    
    # Create filename with timestamp
    report_filename = f"crack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(report_filename, "w") as f:
            f.write(f"CYBERSCAN ZIP CRACKER AUDIT LOG\n")
            f.write(f"Target File: {zip_name}\n") 
            f.write(f"Full Path: {zip_path}\n")
            f.write("-" * 40 + "\n")
            f.write(content)
        
        messagebox.showinfo("Success", f"Report saved as {report_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save: {e}")

def start_cracking():
    def run_crack():
        zip_path = zip_entry.get()
        wordlist_path = wordlist_entry.get()

        if not zip_path:
            messagebox.showwarning("Warning", "Please select a ZIP file!")
            return

        result_display.insert(tk.END, f"--- Scan Started: {datetime.now()} ---\n")
        
        passwords_to_try = []
        if wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='latin-1') as f:
                    passwords_to_try = [line.strip() for line in f]
                result_display.insert(tk.END, "[!] Using external wordlist.\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read wordlist: {e}")
                return
        else:
            passwords_to_try = DEFAULT_PASSWORDS
            result_display.insert(tk.END, "[!] Using built-in default list.\n")

        try:
            zf = zipfile.ZipFile(zip_path)
            for password in passwords_to_try:
                label, color = check_strength(password)
                window.after(0, lambda l=label, c=color: strength_label.config(text=f"Test Strength: {l}", fg=c))
                
                try:
                    zf.extractall(pwd=password.encode('utf-8'))
                    window.after(0, lambda p=password: result_display.insert(tk.END, f"[+] SUCCESS: {p}\n"))
                    messagebox.showinfo("Success", f"Password found: {password}")
                    return
                except:
                    continue
            window.after(0, lambda: result_display.insert(tk.END, "[-] Password not found.\n"))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    threading.Thread(target=run_crack, daemon=True).start()

# --- GUI SETUP ---
window = tk.Tk()
window.title("CyberScan - Zip Cracker Pro")
window.geometry("500x650")

# Input Sections
tk.Label(window, text="Target ZIP File:").pack(pady=5)
zip_frame = tk.Frame(window); zip_frame.pack()
zip_entry = tk.Entry(zip_frame, width=40); zip_entry.pack(side=tk.LEFT, padx=5)
tk.Button(zip_frame, text="Browse", command=browse_zip).pack(side=tk.LEFT)

tk.Label(window, text="Wordlist File (Optional):").pack(pady=5)
word_frame = tk.Frame(window); word_frame.pack()
wordlist_entry = tk.Entry(word_frame, width=40); wordlist_entry.pack(side=tk.LEFT, padx=5)
tk.Button(word_frame, text="Browse", command=browse_wordlist).pack(side=tk.LEFT)

strength_label = tk.Label(window, text="Test Strength: N/A", font=("Arial", 10, "bold"))
strength_label.pack(pady=10)

btn_frame = tk.Frame(window); btn_frame.pack(pady=10)
tk.Button(btn_frame, text="START CRACK", command=start_cracking, bg="red", fg="white", width=15).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="SAVE REPORT", command=save_log, bg="blue", fg="white", width=15).pack(side=tk.LEFT, padx=5)

result_display = scrolledtext.ScrolledText(window, width=55, height=20)
result_display.pack(pady=10)

window.mainloop()