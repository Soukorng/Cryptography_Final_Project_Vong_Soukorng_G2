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
        wiener_attack, low_exponent_attack, rsa_crt_decrypt,
        double_encryption_attack
    )
except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure rsa_core modules are in the correct location")
    raise

class RSACracker:
    def __init__(self, root):
        self.root = root
        self.root.title("CTF RSA Cracker Pro 2025")
        self.root.geometry("1200x960")
        self.root.configure(bg="#0d1117")

        self.stop_flag = False
        self.start_time = None

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.create_ui()

    def create_ui(self):
        main = tk.Frame(self.root, bg="#0d1117")
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Labels
        labels = ["e (public exponent)", "e1 (public exponent 1)", "e2 (public exponent 2)",
                  "n (modulus)", 
                  "c (ciphertext)", "c1 (ciphertext 1)", "c2 (ciphertext 2)",
                  "p (prime 1)", "q (prime 2)", "d (private key)",
                  "dp (d mod p-1)", "dq (d mod q-1)"]

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
            .grid(row=14, column=0, columnspan=2, sticky="we", pady=10)

        # Buttons
        btns = tk.Frame(main, bg="#0d1117")
        btns.grid(row=15, column=0, columnspan=2, pady=15)

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

    # gui/app.py - Update the crack_thread method for better factoring
    def crack_thread(self):
        try:
            if self.stop_flag:
                return

            # Get all values from UI
            e = self.get("e")
            e1 = self.get("e1")
            e2 = self.get("e2")
            n = self.get("n")
            c = self.get("c")
            c1 = self.get("c1")
            c2 = self.get("c2")
            p = self.get("p")
            q = self.get("q")
            d = self.get("d")
            dp = self.get("dp")
            dq = self.get("dq")
            
            m = None  # Initialize m for decrypted message
            
            # =============================================
            # 1. DETERMINE WHICH EXPONENTS WE HAVE
            # =============================================
            exponents = []
            exp_labels = []
            
            if e is not None:
                exponents.append(e)
                exp_labels.append("e")
            if e1 is not None:
                exponents.append(e1)
                exp_labels.append("e1")
            if e2 is not None:
                exponents.append(e2)
                exp_labels.append("e2")
            
            # =============================================
            # 2. DETERMINE WHICH CIPHERTEXT TO USE
            # =============================================
            ciphertexts = []
            cipher_labels = []
            
            if c is not None:
                ciphertexts.append(c)
                cipher_labels.append("c")
            if c1 is not None:
                ciphertexts.append(c1)
                cipher_labels.append("c1")
            if c2 is not None:
                ciphertexts.append(c2)
                cipher_labels.append("c2")
            
            # Use the first ciphertext found
            active_c = ciphertexts[0] if ciphertexts else None
            active_c_label = cipher_labels[0] if cipher_labels else None
            
            # =============================================
            # 3. CHECK FOR DOUBLE ENCRYPTION SCENARIO
            # =============================================
            # Double encryption requires: n, at least 2 exponents, and a ciphertext
            if n and len(exponents) >= 2 and active_c:
                self.log(f"[*] Detected {len(exponents)} exponents and ciphertext in '{active_c_label}'")
                self.log(f"[*] This might be a double encryption scenario")
                
                # If we have exactly 2 exponents, try double_encryption_attack
                if len(exponents) == 2:
                    exp1, exp2 = exponents[0], exponents[1]
                    label1, label2 = exp_labels[0], exp_labels[1]
                    
                    self.log(f"[*] Using double_encryption_attack with {label1}={exp1}, {label2}={exp2}")
                    self.log(f"[*] {label1} bit length: {exp1.bit_length()} bits")
                    self.log(f"[*] {label2} bit length: {exp2.bit_length()} bits")
                    
                    # Try the double encryption attack
                    m = double_encryption_attack(n, exp1, exp2, active_c, log_callback=self.log)
                    
                    if m:
                        self.log(f"[+] Double encryption attack SUCCESS!", "green")
                    else:
                        self.log("[-] Double encryption attack failed")
                
                # If we have 3 exponents, try all pairs
                elif len(exponents) == 3:
                    self.log(f"[*] Trying all 2-exponent combinations for double encryption")
                    
                    # Try all pairs of exponents
                    for i in range(len(exponents)):
                        for j in range(i+1, len(exponents)):
                            exp_i, label_i = exponents[i], exp_labels[i]
                            exp_j, label_j = exponents[j], exp_labels[j]
                            
                            self.log(f"[*] Trying pair ({label_i}, {label_j})")
                            
                            # Try double encryption attack on this pair
                            m = double_encryption_attack(n, exp_i, exp_j, active_c, log_callback=self.log)
                            
                            if m:
                                self.log(f"[+] SUCCESS with pair ({label_i}, {label_j})!", "green")
                                break
                        
                        if m is not None:
                            break
            
            # =============================================
            # CASE 1: We have dp and dq (RSA-CRT)
            # =============================================
            if m is None and active_c and p and q and dp and dq:
                self.log("[+] RSA-CRT detected (dp, dq provided) → Using CRT decryption")
                m = rsa_crt_decrypt(active_c, p, q, dp, dq)
                
                # Compute n if not provided
                if n is None:
                    n = p * q
                    self.log(f"[+] Computed n = p×q = {n}")

            # =============================================
            # CASE 2: We have p, q, e but no d
            # =============================================
            if m is None and p and q:
                if self.stop_flag: 
                    return
                if n is None:
                    n = p * q
                    self.log(f"[+] n = p×q = {n}")
                else:
                    # Verify n = p*q
                    if n != p * q:
                        self.log("[!] Warning: n does not equal p×q!")

                # Use the first available exponent
                active_e = None
                if e is not None:
                    active_e = e
                elif e1 is not None:
                    active_e = e1
                elif e2 is not None:
                    active_e = e2
                    
                if active_e and not d:
                    d = compute_d(p, q, active_e)
                    self.log(f"[+] d computed from p,q,e")

            # =============================================
            # CASE 3: No p, q, dp, dq - try standard attacks
            # =============================================
            if m is None and n and not (p or q or d) and active_c:
                bits = n.bit_length()
                
                # EXTENDED FACTORING: Try up to 2000 bits
                self.log(f"[*] n is {bits}-bit → choosing optimal attack...")
                
                # FIRST: Try low exponent attack if e is small
                active_e = None
                if e is not None:
                    active_e = e
                elif e1 is not None:
                    active_e = e1
                elif e2 is not None:
                    active_e = e2
                
                if active_e and active_e <= 100:
                    self.log(f"[*] Small e={active_e} detected → trying low exponent attack...")
                    m_low = low_exponent_attack(active_e, n, active_c)
                    if m_low:
                        self.log(f"[+] LOW EXPONENT ATTACK SUCCESS! m = {m_low}", "green")
                        m = m_low
                    
                # If low exponent attack didn't work or wasn't applicable
                if m is None:
                    # Try FactorDB first (online database) - works up to 2000 bits
                    self.log(f"[*] Querying FactorDB (factordb.com) for {bits}-bit n...")
                    p_found, q_found = smart_factor_n(n, use_factordb=True)
                    
                    if self.stop_flag: 
                        return

                    if p_found:
                        p, q = sorted([p_found, q_found])
                        self.log(f"[+] FACTORDB SUCCESS! Found p ({p.bit_length()} bits)", "green")
                        self.log(f"[+] FACTORDB SUCCESS! Found q ({q.bit_length()} bits)", "green")

                        if active_e:
                            d = compute_d(p, q, active_e)
                            self.log("[+] d computed from p,q,e")
                    else:
                        # Only try local factorization for numbers up to ~1024 bits
                        if bits <= 1024:
                            self.log("[-] FactorDB failed → trying local factorization...")
                            # Try local methods without FactorDB
                            p_found, q_found = smart_factor_n(n, use_factordb=False)
                            
                            if p_found:
                                p, q = sorted([p_found, q_found])
                                self.log(f"[+] LOCAL FACTORIZATION SUCCESS! p = {p}", "green")
                                self.log(f"[+] LOCAL FACTORIZATION SUCCESS! q = {q}", "green")

                                if active_e:
                                    d = compute_d(p, q, active_e)
                                    self.log("[+] d computed")
                            else:
                                self.log("[-] Local factoring failed → trying Wiener attack...")
                                if active_e:
                                    d = wiener_attack(active_e, n)
                                    if d:
                                        self.log(f"[+] Wiener SUCCESS! d = {d}", "green")
                                else:
                                    self.log("[-] No e provided for Wiener attack")
                        else:
                            self.log(f"[-] Number too large ({bits} bits) for local factoring")
                            self.log("[*] Try providing p and q manually if you have them")

            # =============================================
            # Show result section for all cases that have data
            # =============================================
            values_found = any([e, e1, e2, n, c, c1, c2, p, q, d, dp, dq])
            if values_found:
                self.log("\n" + "═" * 80)
                self.log("RESULT:\n")

                # Show all available values
                dump_pairs = [("e", e), ("e1", e1), ("e2", e2), ("n", n), 
                            ("c", c), ("c1", c1), ("c2", c2),
                            ("p", p), ("q", q), ("d", d), ("dp", dp), ("dq", dq)]
                
                for k, v in dump_pairs:
                    if v is not None:
                        self.log(f"    {k.upper()} = {v}\n")

            # =============================================
            # Decrypt and show plaintext
            # =============================================
            
            # If we already got m from attacks
            if m is not None:
                raw = int_to_bytes(m)
                ascii_text = try_decode(raw)
                
                self.log("\nDecrypted Plaintext:\n")
                self.log(f"  ASCII = {ascii_text}")
                self.log(f"  HEX   = {raw.hex()}")
                self.log(f"  DEC   = {m}")
                self.log(f"  BYTES = {raw}")
                
                if "flag" in ascii_text.lower() or "pico" in ascii_text.lower() or "ctf" in ascii_text.lower() or "CTF" in ascii_text:
                    self.log("\nFLAG FOUND!!!", "red")
                else:
                    self.log("\n[+] Decrypted!")
            
            # Otherwise, try standard RSA decryption
            elif not self.stop_flag and active_c and d and n:
                m = rsa_decrypt(active_c, d, n)
                raw = int_to_bytes(m)
                ascii_text = try_decode(raw)

                self.log("\nDecrypted Plaintext:\n")
                self.log(f"  ASCII = {ascii_text}")
                self.log(f"  HEX   = {raw.hex()}")
                self.log(f"  DEC   = {m}")
                self.log(f"  BYTES = {raw}")

                if "flag" in ascii_text.lower() or "pico" in ascii_text.lower() or "ctf" in ascii_text.lower() or "CTF" in ascii_text:
                    self.log("\nFLAG FOUND!!!", "red")
                else:
                    self.log("\n[+] Decrypted!")

            elif not self.stop_flag and m is None and active_c:
                # Only show this message if we didn't already handle it
                self.log("[!] Cannot decrypt — missing required parameters")

        except Exception as ex:
            self.log(f"\n[ERROR] {ex}\n{traceback.format_exc()}")

        finally:
            if not self.stop_flag:
                self.root.after(0, lambda: self.btn_crack.config(state="normal", text="CRACK RSA"))
                self.log("\nCRACKING COMPLETED!", "done")
            else:
                self.btn_crack.config(state="normal", text="CRACK RSA")