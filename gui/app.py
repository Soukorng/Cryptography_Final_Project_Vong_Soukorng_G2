#gui/app.py
import threading
from tkinter import filedialog
import time
import traceback
import sys
import os
from datetime import datetime
import json
import customtkinter as ctk

# Add the rsa_core directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'rsa_core'))

# Import from rsa_core
try:
    from rsa_core import (
        int_to_bytes, try_decode,
        rsa_decrypt, compute_d, smart_factor_n,
        wiener_attack, low_exponent_attack, rsa_crt_decrypt,
        double_encryption_attack, massive_rsa_attack,
        hastad_broadcast_attack, decrypt_with_phi, decrypt_with_pq,
        even_n_attack, common_modulus_attack, decrypt_with_n_and_prime,
    )
except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure rsa_core modules are in the correct location")
    raise

class RSACracker:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA CRACKER TOOL")
        self.root.geometry("1000x650")
        
        # Configure CustomTkinter theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Custom dark blue color scheme
        self.colors = {
            'bg': '#0f172a',          # Dark blue background
            'card_bg': '#1e293b',     # Card background
            'text': '#e2e8f0',        # Light text
            'accent': '#0ea5e9',      # Cyan accent
            'success': '#10b981',     # Green success
            'warning': '#f59e0b',     # Amber warning
            'error': '#ef4444',       # Red error
            'input_bg': '#0f172a',    # Input background
            'input_fg': '#ffffff',    # Input text
            'button_bg': '#0ea5e9',   # Cyan button
            'button_fg': '#ffffff',   # Button text
            'border': '#334155',      # Border color
        }
        
        # Configure window for responsiveness
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Initialize variables
        self.stop_flag = False
        self.start_time = None
        self.entries = {}
        self.dynamic_fields = {}
        self.results_history = []
        
        # Load saved values if any
        self.saved_values_file = os.path.join(os.path.dirname(__file__), '..', 'saved_values.json')
        
        self.create_modern_ui()
        self.load_saved_values()

    def create_modern_ui(self):
        """Create the modern dark-themed GUI with CustomTkinter"""
        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color=self.colors['bg'])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        main_container.grid_columnconfigure((0, 1), weight=1)
        main_container.grid_rowconfigure(0, weight=1)
        
        # =================== LEFT COLUMN - INPUT ===================
        left_container = ctk.CTkFrame(main_container, 
                                     fg_color=self.colors['card_bg'],
                                     corner_radius=10)
        left_container.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_container.grid_columnconfigure(0, weight=1)
        left_container.grid_rowconfigure(1, weight=1)
        
        # Header for input section
        input_title = ctk.CTkLabel(left_container,
                                  text="🔧 INPUT PARAMETERS",
                                  font=ctk.CTkFont(size=16, weight="bold"),
                                  text_color=self.colors['accent'])
        input_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        # Create scrollable frame for input fields
        self.input_scrollable_frame = ctk.CTkScrollableFrame(left_container,
                                                           fg_color=self.colors['card_bg'])
        self.input_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.input_scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # Create input fields
        self.create_input_fields(self.input_scrollable_frame)
        
        # =================== ACTION BUTTONS ===================
        action_frame = ctk.CTkFrame(left_container, fg_color=self.colors['card_bg'])
        action_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        
        # CRACK button (cyan)
        self.btn_crack = ctk.CTkButton(action_frame,
                                      text="🚀 CRACK RSA",
                                      command=self.start_crack,
                                      font=ctk.CTkFont(size=14, weight="bold"),
                                      height=50,
                                      fg_color=self.colors['button_bg'],
                                      hover_color='#0284c7',
                                      corner_radius=8)
        self.btn_crack.pack(side="left", padx=(0, 10), pady=10)
        
        # Clear button
        btn_clear = ctk.CTkButton(action_frame,
                                 text="🗑️ Reset",
                                 command=self.reset,
                                 font=ctk.CTkFont(size=12),
                                 height=40,
                                 fg_color='#475569',
                                 hover_color='#374151',
                                 corner_radius=8)
        btn_clear.pack(side="left", padx=5, pady=10)
        
        # Save Values button
        btn_save_vals = ctk.CTkButton(action_frame,
                                     text="💾 Save Values",
                                     command=self.save_values,
                                     font=ctk.CTkFont(size=12),
                                     height=40,
                                     fg_color='#475569',
                                     hover_color='#374151',
                                     corner_radius=8)
        btn_save_vals.pack(side="left", padx=5, pady=10)
        
        # =================== RIGHT COLUMN - RESULTS ===================
        right_container = ctk.CTkFrame(main_container,
                                      fg_color=self.colors['card_bg'],
                                      corner_radius=10)
        right_container.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_container.grid_columnconfigure(0, weight=1)
        right_container.grid_rowconfigure(1, weight=1)
        
        # Header for results section
        results_header = ctk.CTkFrame(right_container, fg_color=self.colors['card_bg'])
        results_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        results_header.grid_columnconfigure(0, weight=1)
        
        results_title = ctk.CTkLabel(results_header,
                                   text="📊 RESULTS",
                                   font=ctk.CTkFont(size=16, weight="bold"),
                                   text_color=self.colors['accent'])
        results_title.grid(row=0, column=0, sticky="w")
        
        # Results action buttons
        results_actions = ctk.CTkFrame(results_header, fg_color=self.colors['card_bg'])
        results_actions.grid(row=0, column=1, sticky="e")
        
        self.btn_copy = ctk.CTkButton(results_actions,
                                     text="📋 Copy",
                                     command=self.copy_results,
                                     font=ctk.CTkFont(size=12),
                                     width=80,
                                     height=32,
                                     fg_color='#3498db',
                                     hover_color='#2980b9',
                                     corner_radius=8,
                                     state="disabled")
        self.btn_copy.pack(side="left", padx=2)
        
        self.btn_save = ctk.CTkButton(results_actions,
                                     text="💾 Save",
                                     command=self.save_results,
                                     font=ctk.CTkFont(size=12),
                                     width=80,
                                     height=32,
                                     fg_color='#9b59b6',
                                     hover_color='#8e44ad',
                                     corner_radius=8,
                                     state="disabled")
        self.btn_save.pack(side="left", padx=2)
        
        self.btn_history = ctk.CTkButton(results_actions,
                                        text="📜 History",
                                        command=self.show_history,
                                        font=ctk.CTkFont(size=12),
                                        width=80,
                                        height=32,
                                        fg_color='#475569',
                                        hover_color='#374151',
                                        corner_radius=8)
        self.btn_history.pack(side="left", padx=2)
        
        # Results text area
        results_text_frame = ctk.CTkFrame(right_container,
                                         fg_color=self.colors['card_bg'])
        results_text_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        results_text_frame.grid_columnconfigure(0, weight=1)
        results_text_frame.grid_rowconfigure(0, weight=1)
        
        # Create custom text widget with scrollbar
        self.results_text = ctk.CTkTextbox(results_text_frame,
                                          font=ctk.CTkFont(family="Consolas", size=12),
                                          fg_color=self.colors['input_bg'],
                                          text_color=self.colors['input_fg'],
                                          corner_radius=8)
        self.results_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure text tags
        self.results_text.tag_config("success", foreground=self.colors['success'])
        self.results_text.tag_config("error", foreground=self.colors['error'])
        self.results_text.tag_config("warning", foreground=self.colors['warning'])
        self.results_text.tag_config("flag", foreground=self.colors['accent'])
        self.results_text.tag_config("header", foreground=self.colors['accent'])
        self.results_text.tag_config("param", foreground='#94a3b8')
        self.results_text.tag_config("ascii_red", foreground='#ff6b6b')
        self.results_text.tag_config("history_result", foreground='#f8a5c2')
        
        # Status bar at bottom of main window
        status_frame = ctk.CTkFrame(main_container,
                                   fg_color=self.colors['card_bg'],
                                   corner_radius=10)
        status_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(status_frame,
                                        text="Ready",
                                        font=ctk.CTkFont(size=11),
                                        text_color=self.colors['text'])
        self.status_label.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        
        self.time_label = ctk.CTkLabel(status_frame,
                                      text="",
                                      font=ctk.CTkFont(family="Consolas", size=11),
                                      text_color=self.colors['text'])
        self.time_label.grid(row=0, column=1, sticky="e", padx=20, pady=10)
        
        # Make all containers expandable
        self.make_responsive()
    
    def make_responsive(self):
        """Configure grid weights for responsiveness"""
        # Configure main window
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Update the input scrollable frame to expand
        if hasattr(self, 'input_scrollable_frame'):
            self.input_scrollable_frame.grid_rowconfigure(0, weight=1)
            self.input_scrollable_frame.grid_columnconfigure(0, weight=1)

    def create_input_fields(self, parent):
        """Create input fields with dynamic expansion"""
        # Define main fields and their additional fields
        field_groups = [
            {
                'base': 'e',
                'label': 'Public Exponent (e)',
                'add_fields': ['e1', 'e2'],
                'has_add_button': True
            },
            {
                'base': 'n', 
                'label': 'Modulus (n)',
                'add_fields': ['n1', 'n2', 'n3'],
                'has_add_button': True
            },
            {
                'base': 'c',
                'label': 'Ciphertext (c)',
                'add_fields': ['c1', 'c2', 'c3'],
                'has_add_button': True
            },
            {
                'base': 'p',
                'label': 'Prime p',
                'add_fields': [],
                'has_add_button': False
            },
            {
                'base': 'q',
                'label': 'Prime q', 
                'add_fields': [],
                'has_add_button': False
            },
            {
                'base': 'd',
                'label': 'Private Key (d)',
                'add_fields': ['dp', 'dq'],
                'has_add_button': True
            },
            {
                'base': 'phi',
                'label': 'Phi (φ)',
                'add_fields': [],
                'has_add_button': False
            }
        ]
        
        for i, group in enumerate(field_groups):
            # Create frame for each field group
            field_frame = ctk.CTkFrame(parent, fg_color=self.colors['card_bg'])
            field_frame.pack(fill="x", padx=10, pady=8)
            
            # Main field
            self.create_field_row(field_frame, group['base'], group['label'], group)
            
            # Store dynamic fields info
            if group['add_fields']:
                self.dynamic_fields[group['base']] = {
                    'available': group['add_fields'].copy(),
                    'added': [],
                    'frame': field_frame
                }

    def create_field_row(self, parent, field_name, label, group):
        """Create a single field row with label and entry"""
        # Create a frame to hold everything
        row_frame = ctk.CTkFrame(parent, fg_color=self.colors['card_bg'])
        row_frame.pack(fill="x", padx=(0, 10))
        row_frame.grid_columnconfigure(1, weight=1)
        
        # Label (left side)
        lbl = ctk.CTkLabel(row_frame,
                          text=label + ":",
                          font=ctk.CTkFont(size=12, weight="bold"),
                          text_color=self.colors['text'],
                          anchor="w",
                          width=160)
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 0), pady=5)
        
        # Entry field
        entry = ctk.CTkEntry(row_frame,
                            font=ctk.CTkFont(family="Consolas", size=12),
                            fg_color=self.colors['input_bg'],
                            text_color=self.colors['input_fg'],
                            border_color=self.colors['border'],
                            border_width=2,
                            corner_radius=6)
        entry.grid(row=0, column=1, sticky="ew", padx=0, pady=5)
        
        self.entries[field_name] = entry
        
        # Add button for fields with additional options (right side)
        if group['has_add_button']:
            add_btn = ctk.CTkButton(row_frame,
                                  text="+ Add",
                                  command=lambda f=field_name, g=group: self.add_dynamic_field(f, g),
                                  font=ctk.CTkFont(size=11, weight="bold"),
                                  width=70,
                                  height=30,
                                  fg_color=self.colors['accent'],
                                  hover_color='#0284c7',
                                  corner_radius=6)
            add_btn.grid(row=0, column=2, padx=(5, 0), pady=5)

    def add_dynamic_field(self, base_field, group, specific_field=None):
        """Add a dynamic field below the base field"""
        if specific_field:
            # If specific field is provided, use it if available
            if specific_field not in self.dynamic_fields[base_field]['available']:
                return
            field_name = specific_field
            self.dynamic_fields[base_field]['available'].remove(field_name)
        else:
            # Otherwise use the next available
            if not self.dynamic_fields[base_field]['available']:
                return
            field_name = self.dynamic_fields[base_field]['available'].pop(0)
        
        # Create the dynamic field (indented)
        dynamic_frame = ctk.CTkFrame(self.dynamic_fields[base_field]['frame'], 
                                    fg_color=self.colors['card_bg'])
        dynamic_frame.pack(fill="x", padx=(40, 10), pady=(2, 0))
        dynamic_frame.grid_columnconfigure(1, weight=1)
        
        # Label (indented)
        lbl = ctk.CTkLabel(dynamic_frame,
                          text=f"{field_name}:",
                          font=ctk.CTkFont(size=11),
                          text_color=self.colors['text'],
                          anchor="w",
                          width=115)
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        
        # Entry
        entry = ctk.CTkEntry(dynamic_frame,
                            font=ctk.CTkFont(family="Consolas", size=11),
                            fg_color=self.colors['input_bg'],
                            text_color=self.colors['input_fg'],
                            border_color='#475569',
                            border_width=1,
                            corner_radius=4)
        entry.grid(row=0, column=1, sticky="ew", padx=0, pady=2)
        
        # Remove button (X)
        remove_btn = ctk.CTkButton(dynamic_frame,
                                 text="×",
                                 command=lambda f=field_name, df=dynamic_frame: self.remove_dynamic_field(f, df),
                                 font=ctk.CTkFont(size=12, weight="bold"),
                                 width=30,
                                 height=25,
                                 fg_color='#475569',
                                 hover_color='#374151',
                                 corner_radius=4)
        remove_btn.grid(row=0, column=2, padx=(5, 0), pady=2)
        
        # Store the entry
        self.entries[field_name] = entry
        self.dynamic_fields[base_field]['added'].append({
            'name': field_name,
            'frame': dynamic_frame,
            'entry': entry
        })

    def remove_dynamic_field(self, field_name, frame):
        """Remove a dynamic field"""
        # Find which base field this belongs to
        for base_field, data in self.dynamic_fields.items():
            for idx, field_data in enumerate(data['added']):
                if field_data['name'] == field_name:
                    # Destroy the frame
                    frame.destroy()
                    
                    # Remove from entries
                    if field_name in self.entries:
                        del self.entries[field_name]
                    
                    # Remove from added list and add back to available
                    data['added'].pop(idx)
                    data['available'].insert(0, field_name)
                    return

    def get(self, key):
        """Safely get and convert input values"""
        if key not in self.entries:
            return None
        
        v = self.entries[key].get().strip()
        if not v:
            return None
        
        # Remove any whitespace and newlines
        v = v.replace('\n', '').replace('\r', '').replace(' ', '')
        
        try:
            # Handle hex (0x), binary (0b), and decimal
            return int(v, 0)
        except ValueError as e:
            self.log(f"Invalid input for {key}: '{v}' - {str(e)}", "error")
            return None

    def log(self, msg, tag=None):
        """Thread-safe logging with timestamp"""
        if self.stop_flag:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {msg}"
        
        self.root.after(0, self._safe_log, formatted_msg, tag)

    def _safe_log(self, msg, tag):
        """Safe logging from main thread"""
        self.results_text.insert("end", msg + "\n", tag)
        self.results_text.see("end")
        
        # Enable action buttons
        self.btn_copy.configure(state="normal")
        self.btn_save.configure(state="normal")

    def reset(self):
        """Clear all inputs and results"""
        self.stop_flag = True
        
        # Clear all entry fields
        for entry in self.entries.values():
            if isinstance(entry, ctk.CTkEntry):
                entry.delete(0, 'end')
        
        # Clear results
        self.results_text.delete("1.0", "end")
        
        # Remove all dynamic fields
        for base_field in list(self.dynamic_fields.keys()):
            for field_data in self.dynamic_fields[base_field]['added'][:]:
                self.remove_dynamic_field(field_data['name'], field_data['frame'])
        
        # Reset status
        self.status_label.configure(text="Ready")
        self.time_label.configure(text="")
        self.btn_crack.configure(state="normal", text="🚀 CRACK RSA")
        self.btn_copy.configure(state="disabled")
        self.btn_save.configure(state="disabled")
        self.stop_flag = False

    def start_crack(self):
        """Start the cracking process"""
        if self.stop_flag:
            return
        
        self.stop_flag = False
        self.results_text.delete("1.0", "end")
        self.start_time = time.time()
        
        self.log("=" * 70, "header")
        self.log("RSA CRACKER TOOL", "header")
        self.log("=" * 70, "header")
        self.log(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("")
        
        self.btn_crack.configure(state="disabled", text="⏳ PROCESSING...")
        self.status_label.configure(text="Running attacks...")
        
        # Start cracking in separate thread
        threading.Thread(target=self.crack_thread, daemon=True).start()
        threading.Thread(target=self.timer_thread, daemon=True).start()

    def timer_thread(self):
        """Update timer in status bar"""
        while not self.stop_flag and self.btn_crack.cget("state") == "disabled":
            elapsed = time.time() - self.start_time
            m, s = divmod(elapsed, 60)
            h, m = divmod(m, 60)
            
            if h > 0:
                time_str = f"{int(h)}h {int(m)}m {s:.1f}s"
            elif m > 0:
                time_str = f"{int(m)}m {s:.1f}s"
            else:
                time_str = f"{s:.1f}s"
            
            self.root.after(0, self.time_label.configure, {'text': f"Elapsed: {time_str}"})
            time.sleep(0.1)

    def crack_thread(self):
        """Main cracking logic"""
        try:
            # Collect all parameters with validation
            params = {}
            param_keys = ['e', 'e1', 'e2', 'n', 'n1', 'n2', 'n3', 'c', 'c1', 'c2', 'c3', 'p', 'q', 'd', 'dp', 'dq', 'phi']
            
            for key in param_keys:
                value = self.get(key)
                if value is not None:
                    params[key] = value
            
            # Log collected parameters
            self.log("📋 INPUT PARAMETERS:", "header")
            for key, value in params.items():
                if value is not None:
                    bits = value.bit_length() if value > 0 else 0
                    self.log(f"  {key:>3} = {value} ({bits} bits)", "param")
            
            self.log("")
            
            # Extract values
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
            
             # =================== PRIORITY 1: DECRYPT WITH KNOWN PARAMETERS ===================

            # 1. EVEN N ATTACK (when n is even)
            if not m and n and e and c:
                if n % 2 == 0:
                    self.log("[1] TRYING EVEN N ATTACK...", "header")
                    self.log(f"   • n is even (catastrophic error)")
                    self.log(f"   • p must be 2, q = n/2 = {n//2}")
                    
                    # Use the even_n_attack function
                    m_even = even_n_attack(n, e, c)
                    if m_even:
                        self.log("   ✅ EVEN N ATTACK SUCCESSFUL!", "success")
                        m = m_even

            # 2. COMMON MODULUS ATTACK
            if not m and n and e1 and e2 and c1 and c2:
                    self.log("[2] TRYING COMMON MODULUS ATTACK...", "header")
                    self.log(f"   • Same message encrypted with e1={e1} and e2={e2}")
                    self.log(f"   • n = {n.bit_length()}-bit")
                    self.log(f"   • c1 = {c1.bit_length()}-bit, c2 = {c2.bit_length()}-bit")
                    
                    # Use the common_modulus_attack function
                    m_common = common_modulus_attack(n, e1, e2, c1, c2, log_callback=self.log)
                    
                    if m_common:
                        self.log("   ✅ COMMON MODULUS ATTACK SUCCESSFUL!", "success")
                        m = m_common

            # 3. DECRYPTION WITH PHI (φ)
            if not m and e and phi and c:
                self.log("[3] TRYING DECRYPTION WITH φ(n)...", "header")
                self.log(f"   • e = {e}")
                self.log(f"   • φ = {phi.bit_length()}-bit")
                self.log(f"   • c = {c.bit_length()}-bit")
                
                # Call the unified decrypt_with_phi function
                m_found, n_found, p_found, q_found = decrypt_with_phi(
                    e=e, phi=phi, n=n, d=d, c=c, log_callback=self.log
                )
                
                if m_found:
                    self.log("   ✅ DECRYPTION WITH φ(n) SUCCESSFUL!", "success")
                    m = m_found
                    
                    # Update recovered values for display
                    if n_found and not n:
                        n = n_found
                        self.log(f"   • Recovered n = {n_found.bit_length()}-bit")
                    
                    if p_found and q_found:
                        p = p_found
                        q = q_found
                        self.log(f"   • Recovered p = {p_found.bit_length()}-bit, q = {q_found.bit_length()}-bit")
                else:
                    self.log("   ❌ Decryption with φ(n) failed", "warning")
            
            # 4. STANDARD DECRYPTION WITH p AND q
            if not m and c and p and q:
                self.log("[4] TRYING STANDARD DECRYPTION WITH p AND q...", "header")
                
                # Use the consolidated decrypt_with_pq function
                m_found, n_found, d_found = decrypt_with_pq(
                    c=c, p=p, q=q, e=e, d=d, n=n, log_callback=self.log
                )
                
                if m_found:
                    self.log("   ✅ STANDARD DECRYPTION SUCCESSFUL!", "success")
                    m = m_found
                    
                    # Update recovered values for display
                    if n_found and not n:
                        n = n_found
                        self.log(f"   • Recovered n = {n_found.bit_length()}-bit")
                    
                    if d_found and not d:
                        d = d_found
                        self.log(f"   • Recovered d = {d_found.bit_length()}-bit")
        
            # 5. DECRYPT WITH n AND ONE PRIME (p or q)
            if not m and n and c:
                
                # Case 1: Have n and p, recover q
                if n and p and not q:
                    self.log("[5] DECRYPTION WITH n AND p...", "header")
                    self.log(f"   • n = {n.bit_length()}-bit")
                    self.log(f"   • p = {p.bit_length()}-bit")
                    
                    # Use the decrypt_with_n_and_prime function
                    m_found, n_found, d_found = decrypt_with_n_and_prime(
                        c=c, n=n, prime=p, e=e, log_callback=self.log
                    )
                    if m_found:
                        self.log("   ✅ DECRYPTION WITH n AND p SUCCESSFUL!", "success")
                        m = m_found
                
                # Case 2: Have n and q, recover p
                elif n and q and not p:
                    self.log("[5] DECRYPTION WITH n AND q...", "header")
                    self.log(f"   • n = {n.bit_length()}-bit")
                    self.log(f"   • q = {q.bit_length()}-bit")
                    
                    # Use the decrypt_with_n_and_prime function
                    m_found, n_found, d_found = decrypt_with_n_and_prime(
                        c=c, n=n, prime=q, e=e, log_callback=self.log
                    )
                    if m_found:
                        self.log("   ✅ DECRYPTION WITH n AND q SUCCESSFUL!", "success")
                        m = m_found

            # 6. STANDARD DECRYPTION WITH d
            if not m and c and d and n:
                self.log("[6] TRYING STANDARD DECRYPTION WITH d AND n...", "header")
                self.log(f"   • d = {d.bit_length()}-bit")
                self.log(f"   • n = {n.bit_length()}-bit")
                
                m_standard = rsa_decrypt(c, d, n)
                if m_standard:
                    self.log("   ✅ STANDARD DECRYPTION SUCCESSFUL!", "success")
                    m = m_standard

            # 7. CRT DECRYPTION
            if not m and c and p and q and dp and dq:
                self.log("[7] TRYING CRT DECRYPTION...", "header")
                self.log(f"   • p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
                self.log(f"   • dp = {dp}, dq = {dq}")
                
                m_crt = rsa_crt_decrypt(c, p, q, dp, dq)
                if m_crt:
                    self.log("   ✅ CRT DECRYPTION SUCCESSFUL!", "success")
                    m = m_crt

            # =================== ATTACK STRATEGY ===================
            
            # 8. HÅSTAD BROADCAST ATTACK
            if not m and e is not None and e <= 100:
                # Collect ciphertexts
                ciphertexts = []
                for ct_key in ['c', 'c1', 'c2', 'c3']:
                    if ct_key in params:
                        ciphertexts.append(params[ct_key])
                
                # Collect moduli
                moduli = []
                for n_key in ['n', 'n1', 'n2', 'n3']:
                    if n_key in params:
                        moduli.append(params[n_key])
                
                # We need at least e ciphertexts AND at least e moduli
                if len(ciphertexts) >= e and len(moduli) >= e:
                    self.log("[8] TRYING HÅSTAD BROADCAST ATTACK...", "header")
                    self.log(f"   • Small e = {e}")
                    self.log(f"   • {len(ciphertexts)} ciphertexts available")
                    self.log(f"   • {len(moduli)} moduli available")
                    
                    # Use the improved hastad_broadcast_attack with moduli parameter
                    m_hastad = hastad_broadcast_attack(e, ciphertexts, moduli, 
                                                    log_callback=self.log)
                    if m_hastad:
                        self.log("   ✅ HÅSTAD ATTACK SUCCESSFUL!", "success")
                        m = m_hastad

            # 9. DOUBLE ENCRYPTION ATTACK
            if not m and n and e1 and e2 and c:
                self.log("[9] TRYING DOUBLE ENCRYPTION ATTACK...", "header")
                self.log(f"   • e1 = {e1}, e2 = {e2}")
                self.log(f"   • n = {n.bit_length()}-bit")
                
                m_double = double_encryption_attack(n, e1, e2, c, log_callback=self.log)
                if m_double:
                    self.log("   ✅ DOUBLE ENCRYPTION ATTACK SUCCESSFUL!", "success")
                    m = m_double
            
            # 10. FACTORIZATION ATTEMPTS
            if not m and n and e and c and not p and not q:
                self.log("[10] ATTEMPTING FACTORIZATION...", "header")
                self.log(f"   • n = {n.bit_length()}-bit modulus")
                
                # Try low exponent attack first
                if e and e <= 100:
                    self.log("   • Trying low exponent attack...")
                    m_low = low_exponent_attack(e, n, c)
                    if m_low:
                        self.log("   ✅ LOW EXPONENT ATTACK SUCCESSFUL!", "success")
                        m = m_low
                
                # Try Wiener attack
                if not m:
                    self.log("   • Trying Wiener attack...")
                    d_wiener = wiener_attack(e, n)
                    if d_wiener:
                        self.log("   ✅ WIENER ATTACK SUCCESSFUL!", "success")
                        m = rsa_decrypt(c, d_wiener, n)
                
                # Try factorization
                if not m and n.bit_length() <= 4096:  # Security limit
                    self.log("   • Attempting factorization...")
                    p_found, q_found = smart_factor_n(n, use_factordb=True)
                    if p_found and q_found:
                        self.log("   ✅ FACTORIZATION SUCCESSFUL!", "success")
                        self.log(f"   • p = {p_found.bit_length()}-bit")
                        self.log(f"   • q = {q_found.bit_length()}-bit")
                        
                        # Compute d and decrypt
                        d_computed = compute_d(p_found, q_found, e)
                        m = rsa_decrypt(c, d_computed, n)
            
            # 11. MASSIVE RSA ATTACK (n is prime)
            if not m and n and e and c:
                self.log("[11] TRYING MASSIVE RSA ATTACK...", "header")
                m_massive = massive_rsa_attack(n, e, c, log_callback=self.log)
                if m_massive:
                    self.log("   ✅ MASSIVE RSA ATTACK SUCCESSFUL!", "success")
                    m = m_massive
            
            # =================== DISPLAY RESULTS ===================
            self.log("=" * 70, "header")
            
            if m is not None:
                # Convert to bytes
                raw_bytes = int_to_bytes(m)
                ascii_text = try_decode(raw_bytes)
                hex_text = raw_bytes.hex()
                
                self.log("=" * 70, "header")
                self.log(" 🎉 DECRYPTION SUCCESSFUL!", "success")
                self.log("=" * 70, "header")
                
                self.log(" 📖 DECRYPTED MESSAGE:", "header")
                self.log("-" * 40, "header")
                # UPDATED: Use ascii_red tag for ASCII result
                self.log(f"ASCII:  {ascii_text}", "ascii_red")
                self.log(f"HEX:    {hex_text}")
                self.log(f"Decimal: {m}")
                
                if raw_bytes:
                    self.log(f"Bytes (first 100): {raw_bytes[:100]}{'...' if len(raw_bytes) > 100 else ''}")
                
                # Save to history
                result_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'params': {k: str(v) for k, v in params.items() if v is not None},
                    'result': ascii_text,
                    'hex': hex_text,
                    'decimal': str(m)
                }
                self.results_history.append(result_entry)
                
            else:
                self.log(" ❌ DECRYPTION FAILED", "error")
                self.log("-" * 40)
                self.log("No attack succeeded with the given parameters.")
                self.log(" 💡 SUGGESTIONS:")
                self.log("  • Ensure all required parameters are provided")
                self.log("  • Try adding more ciphertexts for broadcast attacks")
                self.log("  • Check if modulus can be factored online")
                self.log("  • Verify parameter formats (hex with 0x, decimal)")
            
            self.log("=" * 70, "header")
            
        except Exception as ex:
            self.log(f" ❌ ERROR: {str(ex)}", "error")
            self.log(traceback.format_exc(), "error")
            
        finally:
            if not self.stop_flag:
                elapsed = time.time() - self.start_time
                self.root.after(0, lambda: self.btn_crack.configure(state="normal", text="🚀 CRACK RSA"))
                self.root.after(0, lambda: self.status_label.configure(text="Ready"))
                self.root.after(0, lambda: self.time_label.configure(text=f"Completed in {elapsed:.2f}s"))
                self.log(f" ⏱️  Total time: {elapsed:.2f} seconds", "param")

    def copy_results(self):
        """Copy results to clipboard"""
        content = self.results_text.get("1.0", "end").strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log(" 📋 Results copied to clipboard!", "success")

    def save_results(self):
        """Save results to file"""
        content = self.results_text.get("1.0", "end").strip()
        if not content:
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ],
            initialfile=f"rsa_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log(f" 💾 Results saved to: {filename}", "success")
            except Exception as e:
                self.log(f" ❌ Error saving file: {str(e)}", "error")

    def save_values(self):
        """Save current input values to file"""
        try:
            values = {}
            for key, entry in self.entries.items():
                if isinstance(entry, ctk.CTkEntry):
                    value = entry.get().strip()
                    if value:
                        values[key] = value
            
            dynamic_state = {}
            for base_field, data in self.dynamic_fields.items():
                dynamic_state[base_field] = {
                    'added': [field_data['name'] for field_data in data['added']],
                    'available': data['available'].copy()
                }
            
            values['_dynamic_state'] = dynamic_state

            with open(self.saved_values_file, 'w', encoding='utf-8') as f:
                json.dump(values, f, indent=2)
            
            self.log(f" 💾 Input values saved successfully!", "success")
            
        except Exception as e:
            self.log(f" ❌ Error saving values: {str(e)}", "error")

    def load_saved_values(self):
        """Load saved values from file"""
        try:
            if os.path.exists(self.saved_values_file):
                with open(self.saved_values_file, 'r', encoding='utf-8') as f:
                    values = json.load(f)
                
                for key, value in values.items():
                    if key == '_dynamic_state':
                        continue                     
                    
                    if key in self.entries and isinstance(self.entries[key], ctk.CTkEntry):
                        self.entries[key].delete(0, 'end')
                        self.entries[key].insert(0, value)
                # Restore dynamic fields state
                if '_dynamic_state' in values:
                    dynamic_state = values['_dynamic_state']
                    
                    for base_field, state in dynamic_state.items():
                        if base_field in self.dynamic_fields:
                            # Clear any existing dynamic fields for this base
                            for field_data in self.dynamic_fields[base_field]['added'][:]:
                                self.remove_dynamic_field(field_data['name'], field_data['frame'])
                            
                            # Restore the dynamic fields that were saved
                            for field_name in state['added']:
                                # Find the group for this base field
                                for group in self.get_field_groups():
                                    if group['base'] == base_field:
                                        # Add the dynamic field
                                        self.add_dynamic_field(base_field, group, field_name)
                                        
                                        # Set its value if it exists
                                        if field_name in values and field_name in self.entries:
                                            entry = self.entries[field_name]
                                            if isinstance(entry, ctk.CTkEntry):
                                                entry.delete(0, 'end')
                                                entry.insert(0, values[field_name])
                                        break
                            
                            # Update available list
                            self.dynamic_fields[base_field]['available'] = state['available']
                            
                    self.log(f"Loaded {len(values)} saved values", "param")
                    
        except Exception as e:
            # Don't show error if file doesn't exist or is invalid
            pass

    def get_field_groups(self):
        """Return the field groups configuration"""
        return [
            {'base': 'e', 'label': 'Public Exponent (e)', 'add_fields': ['e1', 'e2'], 'has_add_button': True},
            {'base': 'n', 'label': 'Modulus (n)', 'add_fields': ['n1', 'n2', 'n3'], 'has_add_button': True},
            {'base': 'c', 'label': 'Ciphertext (c)', 'add_fields': ['c1', 'c2', 'c3'], 'has_add_button': True},
            {'base': 'p', 'label': 'Prime p', 'add_fields': [], 'has_add_button': False},
            {'base': 'q', 'label': 'Prime q', 'add_fields': [], 'has_add_button': False},
            {'base': 'd', 'label': 'Private Key (d)', 'add_fields': ['dp', 'dq'], 'has_add_button': True},
            {'base': 'phi', 'label': 'Phi (φ)', 'add_fields': [], 'has_add_button': False}
        ]
    
    def show_history(self):
        """Show previous results history"""
        if not self.results_history:
            self.log(" 📜 No history available yet", "warning")
            return
        
        self.log("=" * 70, "header")
        self.log(" 📜 RESULTS HISTORY", "header")
        self.log("=" * 70, "header")
        
        for i, entry in enumerate(reversed(self.results_history[-10:]), 1):  # Show last 10
            self.log(f"[{i}] {entry['timestamp'].split('T')[0]} {entry['timestamp'].split('T')[1][:8]}")
            self.log(f"   Result: {entry['result'][:100]}{'...' if len(entry['result']) > 100 else ''}", "history_result")


