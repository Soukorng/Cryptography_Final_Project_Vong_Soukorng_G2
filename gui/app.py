# gui/app.py
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import time
import traceback
import sys
import os

# Add the rsa_core directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'rsa_core'))

# Now import from rsa_core
try:
    from rsa_core import (
        int_to_bytes, bytes_to_hex, try_decode,
        rsa_decrypt, compute_d, smart_factor_n,
        wiener_attack, low_exponent_attack
    )
except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure rsa_core modules are in the correct location")
    raise

class RSACracker:
    def __init__(self, root):
        self.root = root
        self.root.title("CTF RSA Cracker Pro 2025")
        self.root.geometry("1150x860")
        self.root.configure(bg="#0d1117")

        self.stop_flag = False
        self.start_time = None

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.create_ui()

    def create_ui(self):
        main = tk.Frame(self.root, bg="#0d1117")
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        labels = ["e (public exponent)", "n (modulus)", "c (ciphertext)",
                  "p (prime 1)", "q (prime 2)", "d (private key)"]

        self.entries = {}
        for i, text in enumerate(labels):
            tk.Label(main, text=text + ":", bg="#0d1117", fg="#58a6ff",
                     font=("Consolas", 11)).grid(row=i, column=0, sticky="e", pady=6, padx=5)

            entry = tk.Entry(main, width=90, font=("Consolas", 10),
                             bg="#161b22", fg="#f0f6fc", insertbackground="white")
            entry.grid(row=i, column=1, pady=6, padx=5)

            self.entries[text.split()[0].lower() if '(' not in text else text.split()[0]] = entry

        # Status
        self.status = tk.StringVar(value="Ready")
        tk.Label(main, textvariable=self.status, bg="#0d1117",
                 fg="#79c0ff", font=("Consolas", 10))\
            .grid(row=7, column=0, columnspan=2, sticky="we", pady=10)

        # Buttons
        btns = tk.Frame(main, bg="#0d1117")
        btns.grid(row=8, column=0, columnspan=2, pady=15)

        self.btn_crack = tk.Button(btns, text="CRACK RSA",
                                   command=self.start_crack,
                                   bg="#238636", fg="white",
                                   font=("Arial", 14, "bold"), width=20, height=2)
        self.btn_crack.pack(side="left", padx=10)

        tk.Button(btns, text="Clear", command=self.clear,
                  bg="#da3633", fg="white").pack(side="left", padx=10)

        # Output box
        out = tk.LabelFrame(self.root, text=" Output & Flag ",
                            font=("Arial", 14, "bold"),
                            bg="#0d1117", fg="#ffa657")
        out.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.logbox = scrolledtext.ScrolledText(out, font=("Consolas", 11),
                                                bg="#0d1117", fg="#f0f6fc")
        self.logbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.logbox.tag_config("green", foreground="#00ff00")
        self.logbox.tag_config("red", foreground="#ff5555", font=("Consolas", 16, "bold"))
        self.logbox.tag_config("done", foreground="#00ff88", font=("Consolas", 14, "bold"))

    def get(self, k):
        v = self.entries[k].get().strip()
        return int(v, 0) if v else None

    def log(self, msg, tag=None):
        if self.stop_flag:
            return
        self.logbox.insert("end", msg + "\n", tag)
        self.logbox.see("end")
        self.root.update_idletasks()

    def clear(self):
        self.stop_flag = True
        self.btn_crack.config(state="normal", text="CRACK RSA")
        self.logbox.delete(1.0, "end")

        for e in self.entries.values():
            e.delete(0, "end")

        self.status.set("Ready")
        self.start_time = None

    def start_crack(self):
        self.stop_flag = False
        self.logbox.delete(1.0, "end")

        self.log("RSA Cracker Pro Started... (background thread)", "green")
        self.btn_crack.config(state="disabled", text="WORKING...")

        self.status.set("Running... 0.0s")
        self.start_time = time.time()

        threading.Thread(target=self.crack_thread, daemon=True).start()
        threading.Thread(target=self.timer_thread, daemon=True).start()

    def timer_thread(self):
        while not self.stop_flag and self.btn_crack["state"] == "disabled":
            elapsed = time.time() - self.start_time
            m, s = divmod(elapsed, 60)
            self.status.set(f"Running... {int(m)}m {s:.1f}s")
            time.sleep(0.1)

        if self.stop_flag:
            self.status.set("Stopped")
        else:
            elapsed = time.time() - self.start_time
            m, s = divmod(elapsed, 60)
            self.status.set(f"Finished in {int(m)}m {s:.1f}s")

    def crack_thread(self):
        try:
            if self.stop_flag:
                return

            e = self.get("e")
            n = self.get("n")
            c = self.get("c")
            p = self.get("p")
            q = self.get("q")
            d = self.get("d")

            # If p and q are given →
            if p and q:
                if self.stop_flag: 
                    return
                n = p * q
                self.log(f"[+] n = p×q = {hex(n)}")

                if e and not d:
                    d = compute_d(p, q, e)
                    self.log("[+] d computed from p,q,e")

            # Auto attack if missing values
            if n and not (p or q or d):
                bits = n.bit_length()
                self.log(f"[*] n is {bits}-bit → choosing optimal attack...")
                
                # FIRST: Try low exponent attack if e is small
                if e and c and e <= 100:  # e is small enough to try
                    self.log(f"[*] Small e={e} detected → trying low exponent attack...")
                    m_low = low_exponent_attack(e, n, c)
                    if m_low:
                        self.log(f"[+] LOW EXPONENT ATTACK SUCCESS! m = {hex(m_low)}", "green")
                        
                        # Decrypt directly
                        raw = int_to_bytes(m_low)
                        ascii_text = try_decode(raw)
                        
                        self.log("\nDecrypted Plaintext:")
                        self.log(f"  ASCII = {ascii_text}")
                        self.log(f"  HEX   = {raw.hex()}")
                        self.log(f"  DEC   = {m_low}")
                        
                        if "flag" in ascii_text.lower():
                            self.log("\nFLAG FOUND!!!", "red")
                        return  # Exit early, we're done!
                
                # Try FactorDB first (online database)
                self.log(f"[*] Querying FactorDB (factordb.com)...")
                p_found, q_found = smart_factor_n(n, use_factordb=True)
                
                if self.stop_flag: 
                    return

                if p_found:
                    p, q = sorted([p_found, q_found])
                    self.log(f"[+] FACTORDB SUCCESS! Found p ({p.bit_length()} bits)", "green")
                    self.log(f"[+] FACTORDB SUCCESS! Found q ({q.bit_length()} bits)", "green")

                    if e:
                        d = compute_d(p, q, e)
                        self.log("[+] d computed from p,q,e")
                else:
                    self.log("[-] FactorDB failed → trying local factorization...")
                    # Try local methods without FactorDB
                    p_found, q_found = smart_factor_n(n, use_factordb=False)
                    
                    if p_found:
                        p, q = sorted([p_found, q_found])
                        self.log(f"[+] LOCAL FACTORIZATION SUCCESS! p = {p}", "green")
                        self.log(f"[+] LOCAL FACTORIZATION SUCCESS! q = {q}", "green")

                        if e:
                            d = compute_d(p, q, e)
                            self.log("[+] d computed")
                    else:
                        self.log("[-] Local factoring failed → trying Wiener attack...")
                        if e:
                            d = wiener_attack(e, n)
                            if d:
                                self.log(f"[+] Wiener SUCCESS! d = {hex(d)}", "green")
                        else:
                            self.log("[-] No e provided for Wiener attack")

            # Dump computed values
            self.log("\n" + "═" * 80)
            self.log("RESULT:")

            dump_pairs = [("e", e), ("n", n), ("c", c), ("p", p), ("q", q), ("d", d)]
            for k, v in dump_pairs:
                if v is not None:
                    self.log(f"    {k.upper()} (hex) = {hex(v)}")
                    self.log(f"    {k.upper()} (dec) = {v}\n")

            # Decrypt section
            if not self.stop_flag and c and d and n:
                m = rsa_decrypt(c, d, n)
                raw = int_to_bytes(m)
                ascii_text = try_decode(raw)

                self.log("Decrypted Plaintext:")
                self.log(f"  ASCII = {ascii_text}")
                self.log(f"  HEX   = {raw.hex()}")
                self.log(f"  DEC   = {m}")
                self.log(f"  BYTES = {raw}")

                if "flag" in ascii_text.lower():
                    self.log("\nFLAG FOUND!!!", "red")
                else:
                    self.log("\n[+] Decrypted!")

            elif not self.stop_flag:
                self.log("[!] Cannot decrypt — missing c/d/n")

        except Exception as ex:
            self.log(f"\n[ERROR] {ex}\n{traceback.format_exc()}")

        finally:
            if not self.stop_flag:
                self.root.after(0, lambda: self.btn_crack.config(state="normal", text="CRACK RSA"))
                self.log("\nCRACKING COMPLETED!", "done")
            else:
                self.btn_crack.config(state="normal", text="CRACK RSA")