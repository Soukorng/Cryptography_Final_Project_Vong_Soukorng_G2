"""Main GUI Window"""

import threading
import time
import traceback
import sys
import os
import json
import customtkinter as ctk
from datetime import datetime
from tkinter import filedialog


# Import core modules
from rsa_core.utils.converters import int_to_bytes, try_decode
from rsa_core.decryption.standard import rsa_decrypt, compute_d
from rsa_core.decryption.crt import rsa_crt_decrypt
from rsa_core.decryption.with_phi import decrypt_with_phi
from rsa_core.decryption.with_pq import decrypt_with_pq
from rsa_core.decryption.partial_key import decrypt_with_n_and_prime
from rsa_core.attacks import (
    low_exponent_attack,
    wiener_attack,
    double_encryption_attack,
    massive_rsa_attack,
    hastad_broadcast_attack,
    even_n_attack,
    common_modulus_attack
)
from rsa_core.factorization.smart_factor import smart_factor_n
from gui.widgets.input_panel import InputPanel
from gui.widgets.results_panel import ResultsPanel
from gui.widgets.status_bar import StatusBar
from gui.theme import colors

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class RSACracker:
    """Main RSA Cracker application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("RSA CRACKER")
        self.root.geometry("1000x650")
        
        # Configure theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize components
        self.stop_flag = False
        self.start_time = None
        self.results_history = []
        self.saved_values_file = "saved_values.json"
        
        self.create_ui()
        self.load_saved_values()
    
    def create_ui(self):
        """Create the user interface"""
        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color=colors['bg'])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        main_container.grid_columnconfigure((0, 1), weight=1)
        main_container.grid_rowconfigure(0, weight=1)
        
        # Left column - Input
        self.input_panel = InputPanel(main_container)
        self.input_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Right column - Results
        self.results_panel = ResultsPanel(main_container)
        self.results_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        
        # Status bar
        self.status_bar = StatusBar(main_container)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        
        # Connect signals
        self.input_panel.btn_crack.configure(command=self.start_crack)
        self.input_panel.btn_clear.configure(command=self.reset)
        self.input_panel.btn_save.configure(command=self.save_values)
        
        self.results_panel.btn_copy.configure(command=self.copy_results)
        self.results_panel.btn_save.configure(command=self.save_results)
        self.results_panel.btn_history.configure(command=self.show_history)
    
    def log(self, msg, tag=None):
        """Thread-safe logging"""
        if self.stop_flag:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {msg}"
        
        self.root.after(0, self._safe_log, formatted_msg, tag)
    
    def _safe_log(self, msg, tag):
        """Safe logging from main thread"""
        self.results_panel.results_text.insert("end", msg + "\n", tag)
        self.results_panel.results_text.see("end")
        
        # Enable action buttons
        self.results_panel.btn_copy.configure(state="normal")
        self.results_panel.btn_save.configure(state="normal")
    
    def start_crack(self):
        """Start the cracking process"""
        if self.stop_flag:
            return
        
        self.stop_flag = False
        self.results_panel.clear_results()
        self.start_time = time.time()
        
        self.log("=" * 70, "header")
        self.log("RSA CRACKER", "header")
        self.log("=" * 70, "header")
        self.log(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("")
        
        self.input_panel.set_cracking_state(True)
        self.status_bar.set_status("Running attacks...")
        
        # Start cracking in separate thread
        threading.Thread(target=self.crack_thread, daemon=True).start()
        threading.Thread(target=self.timer_thread, daemon=True).start()
    
    def timer_thread(self):
        """Update timer in status bar"""
        while not self.stop_flag and self.input_panel.btn_crack.cget("state") == "disabled":
            elapsed = time.time() - self.start_time
            self.status_bar.update_timer(elapsed)
            time.sleep(0.1)
    
    def crack_thread(self):
        """Main cracking logic"""
        try:
            # Collect parameters
            params = self.input_panel.get_all_parameters()
            
            # Log parameters
            self.log("📋 INPUT PARAMETERS:", "header")
            for key, value in params.items():
                if value is not None:
                    bits = value.bit_length() if value > 0 else 0
                    self.log(f"  {key:>3} = {value} ({bits} bits)", "param")
            
            self.log("")
            
            # Extract commonly used parameters
            e = params.get('e')
            e1 = params.get('e1')
            e2 = params.get('e2')
            n = params.get('n')
            n1 = params.get('n1')
            n2 = params.get('n2')
            n3 = params.get('n3')
            c = params.get('c')
            c1 = params.get('c1')
            c2 = params.get('c2')
            c3 = params.get('c3')
            p = params.get('p')
            q = params.get('q')
            d = params.get('d')
            dp = params.get('dp')
            dq = params.get('dq')
            phi = params.get('phi')
            
            m = None  # Result
            
            # Run attacks in priority order
            m = self.run_all_attacks(params)
            
            # Display results
            self.display_results(m, params)
            
        except Exception as ex:
            self.log(f"❌ ERROR: {str(ex)}", "error")
            self.log(traceback.format_exc(), "error")
        finally:
            self.finish_cracking()
    
    def run_all_attacks(self, params):
        """Run all RSA attacks in priority order"""
        m = None
        
        # Extract parameters
        e = params.get('e')
        e1 = params.get('e1')
        e2 = params.get('e2')
        n = params.get('n')
        n1 = params.get('n1')
        n2 = params.get('n2')
        n3 = params.get('n3')
        c = params.get('c')
        c1 = params.get('c1')
        c2 = params.get('c2')
        p = params.get('p')
        q = params.get('q')
        d = params.get('d')
        dp = params.get('dp')
        dq = params.get('dq')
        phi = params.get('phi')
        
        # 1. Even N Attack
        if not m and n and e and c:
            m = self.try_even_n_attack(n, e, c)
        
        # 2. Common Modulus Attack
        if not m and n and e1 and e2 and c1 and c2:
            m = self.try_common_modulus_attack(n, e1, e2, c1, c2)
        
        # 3. Decryption with Phi
        if not m and e and phi and c:
            m = self.try_decrypt_with_phi(e, phi, n, d, c)
        
        # 4. Decryption with p and q
        if not m and c and p and q:
            m = self.try_decrypt_with_pq(c, p, q, e, d, n)
        
        # 5. Decryption with n and one prime
        if not m and n and c:
            m = self.try_decrypt_with_partial(n, p, q, e, c)
        
        # 6. Standard decryption with d
        if not m and c and d and n:
            m = self.try_standard_decryption(c, d, n)
        
        # 7. CRT decryption
        if not m and c and p and q and dp and dq:
            m = self.try_crt_decryption(c, p, q, dp, dq)
        
        # 8. Håstad Broadcast Attack
        if not m and e and e <= 100:
            m = self.try_hastad_attack(e, params)
        
        # 9. Double Encryption Attack
        if not m and n and e1 and e2 and c:
            m = self.try_double_encryption_attack(n, e1, e2, c)
        
        # 10. Factorization attempts
        if not m and n and e and c and not p and not q:
            m = self.try_factorization_attacks(n, e, c)
        
        # 11. Massive RSA Attack
        if not m and n and e and c:
            m = self.try_massive_rsa_attack(n, e, c)
        
        return m
    
    def try_even_n_attack(self, n, e, c):
        """Try even n attack"""
        self.log("[1] TRYING EVEN N ATTACK...", "header")
        self.log(f"   • n is even (catastrophic error)")
        self.log(f"   • p must be 2, q = n/2 = {n//2}")

        m = even_n_attack(n, e, c)
        if m:
            self.log("   ✅ EVEN N ATTACK SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def try_common_modulus_attack(self, n, e1, e2, c1, c2):
        """Try common modulus attack"""
        self.log("[2] TRYING COMMON MODULUS ATTACK...", "header")
        self.log(f"   • Same message encrypted with e1={e1} and e2={e2}")
        self.log(f"   • n = {n.bit_length()}-bit")
        self.log(f"   • c1 = {c1.bit_length()}-bit, c2 = {c2.bit_length()}-bit")

        m = common_modulus_attack(n, e1, e2, c1, c2, log_callback=self.log)
        if m:
            self.log("   ✅ COMMON MODULUS ATTACK SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def try_decrypt_with_phi(self, e, phi, n, d, c):
        """Try decryption with phi"""
        self.log("[3] TRYING DECRYPTION WITH φ(n)...", "header")
        self.log(f"   • e = {e}")
        self.log(f"   • φ = {phi.bit_length()}-bit")
        self.log(f"   • c = {c.bit_length()}-bit")

        result = decrypt_with_phi(e=e, phi=phi, n=n, d=d, c=c, log_callback=self.log)
        if result[0]:
            self.log("   ✅ DECRYPTION WITH φ(n) SUCCESSFUL!", "success")
            self.log(f"   • Found m = {result[0]}")
            return result[0]
        return None
    
    def try_decrypt_with_pq(self, c, p, q, e, d, n):
        """Try decryption with p and q"""
        self.log("[4] TRYING STANDARD DECRYPTION WITH p AND q...", "header")
        self.log(f"   • p = {p.bit_length()}-bit")
        self.log(f"   • q = {q.bit_length()}-bit")

        result = decrypt_with_pq(c=c, p=p, q=q, e=e, d=d, n=n, log_callback=self.log)
        if result[0]:
            self.log("   ✅ STANDARD DECRYPTION SUCCESSFUL!", "success")
            self.log(f"   • Found m = {result[0]}")
            return result[0]
        return None
    
    def try_decrypt_with_partial(self, n, p, q, e, c):
        """Try decryption with partial key"""
        if n and p and not q:
            self.log("[5] TRYING DECRYPTION WITH n AND p...", "header")
            self.log(f"   • n = {n.bit_length()}-bit")
            self.log(f"   • p = {p.bit_length()}-bit")

            result = decrypt_with_n_and_prime(c=c, n=n, prime=p, e=e, log_callback=self.log)
            if result[0]:
                self.log("   ✅ DECRYPTION WITH n AND p SUCCESSFUL!", "success")
                self.log(f"   • Found m = {result[0]}")
                return result[0]
        elif n and q and not p:
            self.log("[5] TRYING DECRYPTION WITH n AND q...", "header")
            self.log(f"   • n = {n.bit_length()}-bit")
            self.log(f"   • q = {q.bit_length()}-bit")

            result = decrypt_with_n_and_prime(c=c, n=n, prime=q, e=e, log_callback=self.log)
            if result[0]:
                self.log("   ✅ DECRYPTION WITH n AND q SUCCESSFUL!", "success")
                self.log(f"   • Found m = {result[0]}")
                return result[0]
        return None
    
    def try_standard_decryption(self, c, d, n):
        """Try standard decryption"""
        self.log("[6] TRYING STANDARD DECRYPTION WITH d AND n...", "header")
        self.log(f"   • d = {d.bit_length()}-bit")
        self.log(f"   • n = {n.bit_length()}-bit")

        m = rsa_decrypt(c, d, n)
        if m:
            self.log("   ✅ STANDARD DECRYPTION SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def try_crt_decryption(self, c, p, q, dp, dq):
        """Try CRT decryption"""
        self.log("[7] TRYING CRT DECRYPTION...", "header")
        self.log(f"   • p = {p.bit_length()}-bit")
        self.log(f"   • q = {q.bit_length()}-bit")
        self.log(f"   • dp = {dp.bit_length()}-bit")
        self.log(f"   • dq = {dq.bit_length()}-bit")
        m = rsa_crt_decrypt(c, p, q, dp, dq)
        if m:
            self.log("   ✅ CRT DECRYPTION SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def try_hastad_attack(self, e, params):
        """Try Håstad broadcast attack"""
        # Collect ciphertexts and moduli
        ciphertexts = []
        for ct_key in ['c', 'c1', 'c2', 'c3']:
            if ct_key in params:
                ciphertexts.append(params[ct_key])
        
        moduli = []
        for n_key in ['n', 'n1', 'n2', 'n3']:
            if n_key in params:
                moduli.append(params[n_key])
        
        if len(ciphertexts) >= e and len(moduli) >= e:
            self.log("[8] TRYING HÅSTAD BROADCAST ATTACK...", "header")
            self.log(f"   • Small e = {e}")
            self.log(f"   • ciphertexts = {len(ciphertexts)}")
            self.log(f"   • moduli = {len(moduli)}")
            m = hastad_broadcast_attack(e, ciphertexts, moduli, log_callback=self.log)
            if m:
                self.log("   ✅ HÅSTAD ATTACK SUCCESSFUL!", "success")
                self.log(f"   • Found m = {m}")
            return m
        return None
    
    def try_double_encryption_attack(self, n, e1, e2, c):
        """Try double encryption attack"""
        self.log("[9] TRYING DOUBLE ENCRYPTION ATTACK...", "header")
        self.log(f"   • n = {n.bit_length()}-bit")
        self.log(f"   • e1 = {e1}")
        self.log(f"   • e2 = {e2}")

        m = double_encryption_attack(n, e1, e2, c, log_callback=self.log)
        if m:
            self.log("   ✅ DOUBLE ENCRYPTION ATTACK SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def try_factorization_attacks(self, n, e, c):
        """Try factorization-based attacks"""
        self.log("[10] ATTEMPTING FACTORIZATION...", "header")
        self.log(f"   • n = {n.bit_length()}-bit")
        self.log(f"   • e = {e}")
        
        # Low exponent attack
        if e and e <= 100:
            self.log("   • Trying low exponent attack...")
            m = low_exponent_attack(e, n, c)
            if m:
                self.log("   ✅ LOW EXPONENT ATTACK SUCCESSFUL!", "success")
                self.log(f"   • Found m = {m}")
                return m
        
        # Wiener attack
        self.log("   • Trying Wiener attack...")
        d = wiener_attack(e, n)
        if d:
            self.log("   ✅ WIENER ATTACK SUCCESSFUL!", "success")
            self.log(f"   • Found d = {d}")
            return rsa_decrypt(c, d, n)
        
        # Factorization
        if n.bit_length() <= 4096:
            self.log("   • Attempting factorization...")
            p, q = smart_factor_n(n, use_factordb=True)
            if p and q:
                self.log("   ✅ FACTORIZATION SUCCESSFUL!", "success")
                self.log(f"   • p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
                d = compute_d(p, q, e)
                return rsa_decrypt(c, d, n)
        
        return None
    
    def try_massive_rsa_attack(self, n, e, c):
        """Try massive RSA attack"""
        self.log("[11] TRYING MASSIVE RSA ATTACK...", "header")
        self.log(f"   • n = {n.bit_length()}-bit")
        self.log(f"   • e = {e}")
        m = massive_rsa_attack(n, e, c, log_callback=self.log)
        if m:
            self.log("   ✅ MASSIVE RSA ATTACK SUCCESSFUL!", "success")
            self.log(f"   • Found m = {m}")
        return m
    
    def display_results(self, message, params):
        """Display decryption results"""
        self.log("=" * 70, "header")
        
        if message is not None:
            # Convert to bytes and ASCII
            raw_bytes = int_to_bytes(message)
            ascii_text = try_decode(raw_bytes)
            hex_text = raw_bytes.hex()
            
            self.log(" 🎉 DECRYPTION SUCCESSFUL!", "success")
            self.log("=" * 70, "header")
            self.log(" 📖 DECRYPTED MESSAGE:", "header")
            self.log("-" * 40, "header")
            self.log(f"ASCII:  {ascii_text}", "ascii_red")
            self.log(f"HEX:    {hex_text}")
            self.log(f"Decimal: {message}")
            
            if raw_bytes:
                self.log(f"Bytes (first 100): {raw_bytes[:100]}{'...' if len(raw_bytes) > 100 else ''}")
            
            # Save to history
            self.save_to_history(params, ascii_text, hex_text, message)
        else:
            self.log(" ❌ DECRYPTION FAILED", "error")
            self.log("-" * 40)
            self.log("No attack succeeded with the given parameters.")
            self.log(" 💡 SUGGESTIONS:")
            self.log("  • Ensure all required parameters are provided")
            self.log("  • Check if modulus can be factored online")
            self.log("  • Verify parameter formats (hex with 0x, decimal)")
        
        self.log("=" * 70, "header")
    
    def save_to_history(self, params, ascii_text, hex_text, message):
        """Save successful decryption to history"""
        result_entry = {
            'timestamp': datetime.now().isoformat(),
            'params': {k: str(v) for k, v in params.items() if v is not None},
            'result': ascii_text,
            'hex': hex_text,
            'decimal': str(message)
        }
        self.results_history.append(result_entry)
    
    def finish_cracking(self):
        """Clean up after cracking process"""
        if not self.stop_flag:
            elapsed = time.time() - self.start_time
            self.input_panel.set_cracking_state(False)
            self.status_bar.set_status("Ready")
            self.status_bar.set_time(f"Completed in {elapsed:.2f}s")
            self.log(f" ⏱️  Total time: {elapsed:.2f} seconds", "param")
    
    def reset(self):
        """Clear all inputs and results"""
        self.stop_flag = True
        self.input_panel.clear_all()
        self.results_panel.clear_results()
        self.status_bar.clear()
        self.input_panel.set_cracking_state(False)
        self.stop_flag = False
    
    def save_values(self):
        """Save current input values to file"""
        try:
            values = self.input_panel.get_all_values()
            dynamic_state = self.input_panel.get_dynamic_state()
            
            values['_dynamic_state'] = dynamic_state
            
            with open(self.saved_values_file, 'w', encoding='utf-8') as f:
                json.dump(values, f, indent=2)
            
            self.log(" 💾 Input values saved successfully!", "success")
        except Exception as e:
            self.log(f" ❌ Error saving values: {str(e)}", "error")
    
    def load_saved_values(self):
        """Load saved values from file"""
        try:
            if os.path.exists(self.saved_values_file):
                with open(self.saved_values_file, 'r', encoding='utf-8') as f:
                    values = json.load(f)
                
                self.input_panel.load_values(values)
                self.log(f"Loaded saved values", "param")
        except:
            pass
    
    def copy_results(self):
        """Copy results to clipboard"""
        content = self.results_panel.get_results()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log(" 📋 Results copied to clipboard!", "success")
    
    def save_results(self):
        """Save results to file"""
        content = self.results_panel.get_results()
        if not content:
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"rsa_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log(f" 💾 Results saved to: {filename}", "success")
            except Exception as e:
                self.log(f" ❌ Error saving file: {str(e)}", "error")
    
    def show_history(self):
        """Show previous results history"""
        if not self.results_history:
            self.log(" 📜 No history available yet", "warning")
            return
        
        self.log("=" * 70, "header")
        self.log(" 📜 RESULTS HISTORY", "header")
        self.log("=" * 70, "header")
        
        for i, entry in enumerate(reversed(self.results_history[-10:]), 1):
            self.log(f"[{i}] {entry['timestamp'].split('T')[0]} {entry['timestamp'].split('T')[1][:8]}")
            self.log(f"   Result: {entry['result'][:100]}{'...' if len(entry['result']) > 100 else ''}", "history_result")