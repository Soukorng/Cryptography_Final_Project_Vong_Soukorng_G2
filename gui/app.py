# gui/app.py - Modern RSA Cracker with Dark Blue Theme
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import time
import traceback
import sys
import os
from datetime import datetime
import json

# Add the rsa_core directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'rsa_core'))

# Import from rsa_core
try:
    from rsa_core import (
        int_to_bytes, bytes_to_hex, try_decode,
        rsa_decrypt, compute_d, smart_factor_n,
        wiener_attack, low_exponent_attack, rsa_crt_decrypt,
        double_encryption_attack, massive_rsa_attack,
        hastad_broadcast_attack, compute_d_from_phi
    )
except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure rsa_core modules are in the correct location")
    raise

class RSACracker:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA CRACKER TOOL")
        self.root.geometry("1200x900")
        
        # Secure dark blue color scheme
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
        
        # Configure window
        self.root.configure(bg=self.colors['bg'])
        
        # Configure ttk style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
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

    def configure_styles(self):
        """Configure ttk styles for modern dark theme"""
        # Configure frame styles
        self.style.configure('Card.TFrame',
                           background=self.colors['card_bg'],
                           borderwidth=1,
                           relief='solid')
        
        # Configure label styles
        self.style.configure('Title.TLabel',
                           background=self.colors['bg'],
                           foreground=self.colors['accent'])
        
        self.style.configure('Subtitle.TLabel',
                           background=self.colors['bg'],
                           foreground=self.colors['text'])
        
        # Configure button styles
        self.style.configure('Crack.TButton',
                           background=self.colors['button_bg'],
                           foreground=self.colors['button_fg'],
                           borderwidth=0)
        
        self.style.map('Crack.TButton',
                      background=[('active', '#0284c7')])
        
        self.style.configure('Action.TButton',
                           background='#475569',
                           foreground='white',
                           borderwidth=0)
        
        # Configure scrollbar
        self.style.configure('Custom.Vertical.TScrollbar',
                           background='#334155',
                           darkcolor='#334155',
                           lightcolor='#334155',
                           troughcolor=self.colors['card_bg'],
                           bordercolor=self.colors['card_bg'],
                           arrowcolor=self.colors['text'])

    def create_modern_ui(self):
        """Create the modern dark-themed GUI"""
        # Main container with two equal halves
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create two equal columns
        main_container.columnconfigure(0, weight=1)  # Left column (Input)
        main_container.columnconfigure(1, weight=1)  # Right column (Results)
        main_container.rowconfigure(0, weight=1)
        
        # =================== LEFT COLUMN - INPUT ===================
        left_container = ttk.Frame(main_container, style='Card.TFrame')
        left_container.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        
        # Header for input section
        input_header = ttk.Frame(left_container, style='Card.TFrame')
        input_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        input_title = tk.Label(input_header,
                             text="🔧 INPUT PARAMETERS",
                             bg=self.colors['card_bg'],
                             fg=self.colors['accent'],
                             font=('Arial', 14, 'bold'))
        input_title.pack(side=tk.LEFT)
        
        # Create scrollable input area
        input_canvas = tk.Canvas(left_container,
                                bg=self.colors['card_bg'],
                                highlightthickness=0)
        input_scrollbar = ttk.Scrollbar(left_container,
                                       orient='vertical',
                                       command=input_canvas.yview,
                                       style='Custom.Vertical.TScrollbar')
        input_scrollable_frame = ttk.Frame(input_canvas, style='Card.TFrame')
        
        input_scrollable_frame.bind(
            "<Configure>",
            lambda e: input_canvas.configure(scrollregion=input_canvas.bbox("all"))
        )
        
        canvas_window = input_canvas.create_window((0, 0),
                                                  window=input_scrollable_frame,
                                                  anchor="nw")
        
        def configure_canvas(event):
            input_canvas.itemconfig(canvas_window, width=event.width)
        
        input_canvas.bind('<Configure>', configure_canvas)
        input_canvas.configure(yscrollcommand=input_scrollbar.set)
        
        # Pack canvas and scrollbar
        input_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 20))
        
        # Create input fields in scrollable frame
        self.create_input_fields(input_scrollable_frame)
        
        # =================== ACTION BUTTONS ===================
        # Create a separate frame for action buttons at the bottom of left column
        action_frame = ttk.Frame(left_container, style='Card.TFrame')
        action_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 20))
        
        # CRACK button (cyan)
        self.btn_crack = tk.Button(action_frame,
                                 text="🚀 CRACK RSA",
                                 command=self.start_crack,
                                 bg=self.colors['button_bg'],
                                 fg=self.colors['button_fg'],
                                 font=('Arial', 12, 'bold'),
                                 padx=30,
                                 pady=15,
                                 bd=0,
                                 relief='flat',
                                 cursor='hand2')
        self.btn_crack.pack(side=tk.LEFT, padx=(0, 10), pady=10)
        
        # Clear button
        btn_clear = tk.Button(action_frame,
                            text="🗑️ Clear All",
                            command=self.clear_all,
                            bg='#475569',
                            fg='white',
                            font=('Arial', 10),
                            padx=20,
                            pady=10,
                            bd=0,
                            relief='flat',
                            cursor='hand2')
        btn_clear.pack(side=tk.LEFT, padx=5, pady=10)
        
        # Save Values button
        btn_save_vals = tk.Button(action_frame,
                                text="💾 Save Values",
                                command=self.save_values,
                                bg='#475569',
                                fg='white',
                                font=('Arial', 10),
                                padx=20,
                                pady=10,
                                bd=0,
                                relief='flat',
                                cursor='hand2')
        btn_save_vals.pack(side=tk.LEFT, padx=5, pady=10)
        
        # =================== RIGHT COLUMN - RESULTS ===================
        right_container = ttk.Frame(main_container, style='Card.TFrame')
        right_container.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        
        # Header for results section
        results_header = ttk.Frame(right_container, style='Card.TFrame')
        results_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        results_title = tk.Label(results_header,
                               text="📊 RESULTS",
                               bg=self.colors['card_bg'],
                               fg=self.colors['accent'],
                               font=('Arial', 14, 'bold'))
        results_title.pack(side=tk.LEFT)
        
        # Results action buttons
        results_actions = tk.Frame(results_header, bg=self.colors['card_bg'])
        results_actions.pack(side=tk.RIGHT)
        
        self.btn_copy = tk.Button(results_actions,
                                text="📋 Copy",
                                command=self.copy_results,
                                bg='#3498db',
                                fg='white',
                                font=('Arial', 10),
                                padx=15,
                                pady=5,
                                bd=0,
                                relief='flat',
                                cursor='hand2',
                                state='disabled')
        self.btn_copy.pack(side=tk.LEFT, padx=2)
        
        self.btn_save = tk.Button(results_actions,
                                text="💾 Save",
                                command=self.save_results,
                                bg='#9b59b6',
                                fg='white',
                                font=('Arial', 10),
                                padx=15,
                                pady=5,
                                bd=0,
                                relief='flat',
                                cursor='hand2',
                                state='disabled')
        self.btn_save.pack(side=tk.LEFT, padx=2)
        
        self.btn_history = tk.Button(results_actions,
                                   text="📜 History",
                                   command=self.show_history,
                                   bg='#475569',
                                   fg='white',
                                   font=('Arial', 10),
                                   padx=15,
                                   pady=5,
                                   bd=0,
                                   relief='flat',
                                   cursor='hand2')
        self.btn_history.pack(side=tk.LEFT, padx=2)
        
        # Results text area
        results_text_frame = ttk.Frame(right_container, style='Card.TFrame')
        results_text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Create custom text widget with scrollbar
        text_frame = tk.Frame(results_text_frame, bg=self.colors['input_bg'])
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = tk.Text(text_frame,
                                   wrap=tk.WORD,
                                   font=('Consolas', 10),
                                   bg=self.colors['input_bg'],
                                   fg=self.colors['input_fg'],
                                   insertbackground=self.colors['accent'],
                                   relief='flat',
                                   padx=15,
                                   pady=15)
        
        text_scrollbar = ttk.Scrollbar(text_frame,
                                      orient='vertical',
                                      command=self.results_text.yview,
                                      style='Custom.Vertical.TScrollbar')
        
        self.results_text.configure(yscrollcommand=text_scrollbar.set)
        
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text tags - UPDATED: Added ascii_red tag
        self.results_text.tag_config("success", foreground=self.colors['success'], font=('Consolas', 10, 'bold'))
        self.results_text.tag_config("error", foreground=self.colors['error'])
        self.results_text.tag_config("warning", foreground=self.colors['warning'])
        self.results_text.tag_config("flag", foreground=self.colors['accent'], font=('Consolas', 12, 'bold'))
        self.results_text.tag_config("header", font=('Consolas', 11, 'bold'))
        self.results_text.tag_config("param", foreground='#94a3b8')
        self.results_text.tag_config("ascii_red", foreground='#ff6b6b', font=('Consolas', 10, 'bold'))  # Red for ASCII
        self.results_text.tag_config("history_result", foreground='#f8a5c2', font=('Consolas', 10))  # Pink color
        
        # Status bar at bottom of main window
        status_frame = ttk.Frame(main_container, style='Card.TFrame')
        status_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(10, 0))
        
        self.status_label = tk.Label(status_frame,
                                   text="Ready",
                                   bg=self.colors['card_bg'],
                                   fg=self.colors['text'],
                                   font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.time_label = tk.Label(status_frame,
                                 text="",
                                 bg=self.colors['card_bg'],
                                 fg=self.colors['text'],
                                 font=('Consolas', 9))
        self.time_label.pack(side=tk.RIGHT, padx=20, pady=10)

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
                'add_fields': [],
                'has_add_button': False
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
            }
        ]
        
        for i, group in enumerate(field_groups):
            # Create frame for each field group
            field_frame = ttk.Frame(parent, style='Card.TFrame')
            field_frame.pack(fill=tk.X, padx=10, pady=8)
            
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
        row_frame = tk.Frame(parent, bg=self.colors['card_bg'])
        row_frame.pack(fill=tk.X, padx=(0, 10))
        
        # Label (left side)
        lbl_frame = tk.Frame(row_frame, bg=self.colors['card_bg'])
        lbl_frame.pack(side=tk.LEFT, padx=(10, 5))
        
        lbl = tk.Label(lbl_frame,
                      text=label + ":",
                      bg=self.colors['card_bg'],
                      fg=self.colors['text'],
                      font=('Arial', 10, 'bold'),
                      anchor='w',
                      width=20)
        lbl.pack(anchor='w')
        
        # Entry field with rounded corners (center)
        entry_frame = tk.Frame(row_frame,
                              bg=self.colors['input_bg'],
                              highlightbackground=self.colors['border'],
                              highlightthickness=2)
        entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        entry = tk.Entry(entry_frame,
                        font=('Consolas', 10),
                        bg=self.colors['input_bg'],
                        fg=self.colors['input_fg'],
                        insertbackground=self.colors['accent'],
                        relief='flat',
                        bd=0)
        entry.pack(fill=tk.BOTH, padx=12, pady=8, ipady=4)
        
        self.entries[field_name] = entry
        
        # Add button for fields with additional options (right side)
        if group['has_add_button']:
            btn_frame = tk.Frame(row_frame, bg=self.colors['card_bg'])
            btn_frame.pack(side=tk.RIGHT, padx=(0, 5))
            
            add_btn = tk.Button(btn_frame,
                              text="+ Add",
                              command=lambda f=field_name, g=group: self.add_dynamic_field(f, g),
                              bg=self.colors['accent'],
                              fg='white',
                              font=('Arial', 9, 'bold'),
                              padx=12,
                              pady=4,
                              bd=0,
                              relief='flat',
                              cursor='hand2')
            add_btn.pack()

    def add_dynamic_field(self, base_field, group):
        """Add a dynamic field below the base field"""
        if not self.dynamic_fields[base_field]['available']:
            return
        
        # Get next available field
        field_name = self.dynamic_fields[base_field]['available'].pop(0)
        
        # Create the dynamic field
        dynamic_frame = tk.Frame(self.dynamic_fields[base_field]['frame'], bg=self.colors['card_bg'])
        dynamic_frame.pack(fill=tk.X, padx=(40, 10), pady=(5, 0))  # Indented
        
        # Label (indented)
        lbl_frame = tk.Frame(dynamic_frame, bg=self.colors['card_bg'])
        lbl_frame.pack(side=tk.LEFT, padx=(0, 5))
        
        lbl = tk.Label(lbl_frame,
                      text=f"{field_name}:",
                      bg=self.colors['card_bg'],
                      fg=self.colors['text'],
                      font=('Arial', 9),
                      anchor='w',
                      width=18)
        lbl.pack(anchor='w')
        
        # Entry
        entry_frame = tk.Frame(dynamic_frame,
                              bg=self.colors['input_bg'],
                              highlightbackground='#475569',
                              highlightthickness=1)
        entry_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        entry = tk.Entry(entry_frame,
                        font=('Consolas', 9),
                        bg=self.colors['input_bg'],
                        fg=self.colors['input_fg'],
                        insertbackground=self.colors['accent'],
                        relief='flat',
                        bd=0)
        entry.pack(fill=tk.BOTH, padx=10, pady=6, ipady=3)
        
        # Remove button (X)
        remove_btn = tk.Button(dynamic_frame,
                             text="×",
                             command=lambda f=field_name, df=dynamic_frame: self.remove_dynamic_field(f, df),
                             bg='#475569',
                             fg='white',
                             font=('Arial', 9, 'bold'),
                             padx=8,
                             pady=0,
                             bd=0,
                             relief='flat',
                             cursor='hand2')
        remove_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
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
        self.btn_copy.config(state='normal')
        self.btn_save.config(state='normal')

    def clear_all(self):
        """Clear all inputs and results"""
        self.stop_flag = True
        
        # Clear all entry fields
        for entry in self.entries.values():
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
        
        # Clear results
        self.results_text.delete(1.0, tk.END)
        
        # Remove all dynamic fields
        for base_field in list(self.dynamic_fields.keys()):
            for field_data in self.dynamic_fields[base_field]['added'][:]:
                self.remove_dynamic_field(field_data['name'], field_data['frame'])
        
        # Reset status
        self.status_label.config(text="Ready")
        self.time_label.config(text="")
        self.btn_crack.config(state='normal', text="🚀 CRACK RSA")
        self.btn_copy.config(state='disabled')
        self.btn_save.config(state='disabled')
        self.stop_flag = False

    def start_crack(self):
        """Start the cracking process"""
        if self.stop_flag:
            return
        
        self.stop_flag = False
        self.results_text.delete(1.0, tk.END)
        self.start_time = time.time()
        
        self.log("=" * 70, "header")
        self.log("RSA CRACKER TOOL", "header")
        self.log("=" * 70, "header")
        self.log(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("")
        
        self.btn_crack.config(state='disabled', text="⏳ PROCESSING...")
        self.status_label.config(text="Running attacks...")
        
        # Start cracking in separate thread
        threading.Thread(target=self.crack_thread, daemon=True).start()
        threading.Thread(target=self.timer_thread, daemon=True).start()

    def timer_thread(self):
        """Update timer in status bar"""
        while not self.stop_flag and self.btn_crack["state"] == "disabled":
            elapsed = time.time() - self.start_time
            m, s = divmod(elapsed, 60)
            h, m = divmod(m, 60)
            
            if h > 0:
                time_str = f"{int(h)}h {int(m)}m {s:.1f}s"
            elif m > 0:
                time_str = f"{int(m)}m {s:.1f}s"
            else:
                time_str = f"{s:.1f}s"
            
            self.root.after(0, self.time_label.config, {'text': f"Elapsed: {time_str}"})
            time.sleep(0.1)

    def crack_thread(self):
        """Main cracking logic - SECURE VERSION"""
        try:
            # Collect all parameters with validation
            params = {}
            param_keys = ['e', 'e1', 'e2', 'n', 'c', 'c1', 'c2', 'c3', 'p', 'q', 'd', 'dp', 'dq']
            
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
            c = params.get('c')
            c1 = params.get('c1')
            c2 = params.get('c2')
            c3 = params.get('c3')
            p = params.get('p')
            q = params.get('q')
            d = params.get('d')
            dp = params.get('dp')
            dq = params.get('dq')
            
            m = None  # Result
            
            # =================== ATTACK STRATEGY ===================
            
            # 1. HÅSTAD BROADCAST ATTACK
            if not m and e is not None and e <= 100:
                ciphertexts = []
                for ct_key in ['c', 'c1', 'c2', 'c3']:
                    if ct_key in params:
                        ciphertexts.append(params[ct_key])
                
                if len(ciphertexts) >= 3:  # Need at least 3 for e=3
                    self.log("[1] TRYING HÅSTAD BROADCAST ATTACK...", "header")
                    self.log(f"   • Small e = {e}")
                    self.log(f"   • {len(ciphertexts)} ciphertexts available")
                    
                    m_hastad = hastad_broadcast_attack(e, ciphertexts)
                    if m_hastad:
                        self.log("   ✅ HÅSTAD ATTACK SUCCESSFUL!", "success")
                        m = m_hastad
            
            # 2. DOUBLE ENCRYPTION ATTACK
            if not m and n and e1 and e2 and c:
                self.log("[2] TRYING DOUBLE ENCRYPTION ATTACK...", "header")
                self.log(f"   • e1 = {e1}, e2 = {e2}")
                self.log(f"   • n = {n.bit_length()}-bit")
                
                m_double = double_encryption_attack(n, e1, e2, c, log_callback=self.log)
                if m_double:
                    self.log("   ✅ DOUBLE ENCRYPTION ATTACK SUCCESSFUL!", "success")
                    m = m_double
            
            # 3. CRT DECRYPTION
            if not m and c and p and q and dp and dq:
                self.log("[3] TRYING CRT DECRYPTION...", "header")
                self.log(f"   • p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
                self.log(f"   • dp = {dp}, dq = {dq}")
                
                m_crt = rsa_crt_decrypt(c, p, q, dp, dq)
                if m_crt:
                    self.log("   ✅ CRT DECRYPTION SUCCESSFUL!", "success")
                    m = m_crt
            
            # 4. STANDARD DECRYPTION WITH D
            if not m and c and d and n:
                self.log("[4] TRYING STANDARD DECRYPTION...", "header")
                self.log(f"   • d = {d.bit_length()}-bit")
                self.log(f"   • n = {n.bit_length()}-bit")
                
                m_standard = rsa_decrypt(c, d, n)
                if m_standard:
                    self.log("   ✅ STANDARD DECRYPTION SUCCESSFUL!", "success")
                    m = m_standard
            
            # 5. FACTORIZATION ATTEMPTS
            if not m and n and e and c and not p and not q:
                self.log("[5] ATTEMPTING FACTORIZATION...", "header")
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
            
            # 6. MASSIVE RSA ATTACK (n is prime)
            if not m and n and e and c:
                self.log("[6] TRYING MASSIVE RSA ATTACK...", "header")
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
                self.log("🎉 DECRYPTION SUCCESSFUL!", "success")
                self.log("=" * 70, "header")
                
                self.log("\n📖 DECRYPTED MESSAGE:")
                self.log("-" * 40)
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
                self.log("❌ DECRYPTION FAILED", "error")
                self.log("-" * 40)
                self.log("No attack succeeded with the given parameters.")
                self.log("\n💡 SUGGESTIONS:")
                self.log("  • Ensure all required parameters are provided")
                self.log("  • Try adding more ciphertexts for broadcast attacks")
                self.log("  • Check if modulus can be factored online")
                self.log("  • Verify parameter formats (hex with 0x, decimal)")
            
            self.log("=" * 70, "header")
            
        except Exception as ex:
            self.log(f"\n❌ ERROR: {str(ex)}", "error")
            self.log(traceback.format_exc(), "error")
            
        finally:
            if not self.stop_flag:
                elapsed = time.time() - self.start_time
                self.root.after(0, self.btn_crack.config, {'state': 'normal', 'text': '🚀 CRACK RSA'})
                self.root.after(0, self.status_label.config, {'text': 'Ready'})
                self.root.after(0, self.time_label.config, {'text': f'Completed in {elapsed:.2f}s'})
                self.log(f"\n⏱️  Total time: {elapsed:.2f} seconds", "param")

    def copy_results(self):
        """Copy results to clipboard"""
        content = self.results_text.get(1.0, tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log("\n📋 Results copied to clipboard!", "success")

    def save_results(self):
        """Save results to file"""
        content = self.results_text.get(1.0, tk.END).strip()
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
                self.log(f"\n💾 Results saved to: {filename}", "success")
            except Exception as e:
                self.log(f"\n❌ Error saving file: {str(e)}", "error")

    def save_values(self):
        """Save current input values to file"""
        try:
            values = {}
            for key, entry in self.entries.items():
                if isinstance(entry, tk.Entry):
                    value = entry.get().strip()
                    if value:
                        values[key] = value
            
            with open(self.saved_values_file, 'w', encoding='utf-8') as f:
                json.dump(values, f, indent=2)
            
            self.log(f"\n💾 Input values saved successfully!", "success")
            
        except Exception as e:
            self.log(f"\n❌ Error saving values: {str(e)}", "error")

    def load_saved_values(self):
        """Load saved values from file"""
        try:
            if os.path.exists(self.saved_values_file):
                with open(self.saved_values_file, 'r', encoding='utf-8') as f:
                    values = json.load(f)
                
                for key, value in values.items():
                    if key in self.entries and isinstance(self.entries[key], tk.Entry):
                        self.entries[key].delete(0, tk.END)
                        self.entries[key].insert(0, value)
                
                self.log(f"Loaded {len(values)} saved values", "param")
                
        except Exception as e:
            # Don't show error if file doesn't exist or is invalid
            pass

    def show_history(self):
        """Show previous results history"""
        if not self.results_history:
            self.log("\n📜 No history available yet", "warning")
            return
        
        self.log("=" * 70, "header")
        self.log("📜 RESULTS HISTORY", "header")
        self.log("=" * 70, "header")
        
        for i, entry in enumerate(reversed(self.results_history[-5:]), 1):  # Show last 5
            self.log(f"\n[{i}] {entry['timestamp'].split('T')[0]} {entry['timestamp'].split('T')[1][:8]}")
            self.log(f"   Result: {entry['result'][:100]}{'...' if len(entry['result']) > 100 else ''}", "history_result")

# Main entry
if __name__ == "__main__":
    root = tk.Tk()
    app = RSACracker(root)
    root.mainloop()