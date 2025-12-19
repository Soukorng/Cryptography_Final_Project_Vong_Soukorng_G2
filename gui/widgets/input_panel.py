"""Input Panel Widget"""

import customtkinter as ctk
from gui.theme import colors

class InputPanel:
    """Panel for input parameters"""
    
    def __init__(self, parent):
        self.parent = parent
        self.entries = {}
        self.dynamic_fields = {}
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create input panel widgets"""
        self.container = ctk.CTkFrame(self.parent, fg_color=colors['card_bg'], corner_radius=10)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(1, weight=1)
        
        # Header
        title = ctk.CTkLabel(self.container,
                           text="🔧 INPUT PARAMETERS",
                           font=ctk.CTkFont(size=16, weight="bold"),
                           text_color=colors['accent'])
        title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        # Scrollable input fields
        self.scrollable_frame = ctk.CTkScrollableFrame(self.container, fg_color=colors['card_bg'])
        self.scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.create_input_fields()
        
        # Action buttons
        action_frame = ctk.CTkFrame(self.container, fg_color=colors['card_bg'])
        action_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        
        self.btn_crack = ctk.CTkButton(action_frame,
                                      text="🚀 CRACK RSA",
                                      font=ctk.CTkFont(size=14, weight="bold"),
                                      height=50,
                                      fg_color=colors['button_bg'],
                                      hover_color='#0284c7',
                                      corner_radius=8)
        self.btn_crack.pack(side="left", padx=(0, 10), pady=10)
        
        self.btn_clear = ctk.CTkButton(action_frame,
                                     text="🗑️ Reset",
                                     font=ctk.CTkFont(size=12),
                                     height=40,
                                     fg_color='#475569',
                                     hover_color='#374151',
                                     corner_radius=8)
        self.btn_clear.pack(side="left", padx=5, pady=10)
        
        self.btn_save = ctk.CTkButton(action_frame,
                                     text="💾 Save Values",
                                     font=ctk.CTkFont(size=12),
                                     height=40,
                                     fg_color='#475569',
                                     hover_color='#374151',
                                     corner_radius=8)
        self.btn_save.pack(side="left", padx=5, pady=10)
    
    def create_input_fields(self):
        """Create input fields"""
        field_groups = [
            {'base': 'e', 'label': 'Public Exponent (e)', 'add_fields': ['e1', 'e2']},
            {'base': 'n', 'label': 'Modulus (n)', 'add_fields': ['n1', 'n2', 'n3']},
            {'base': 'c', 'label': 'Ciphertext (c)', 'add_fields': ['c1', 'c2', 'c3']},
            {'base': 'p', 'label': 'Prime p', 'add_fields': []},
            {'base': 'q', 'label': 'Prime q', 'add_fields': []},
            {'base': 'd', 'label': 'Private Key (d)', 'add_fields': ['dp', 'dq']},
            {'base': 'phi', 'label': 'Phi (φ)', 'add_fields': []},
        ]
        
        for group in field_groups:
            self.create_field_group(group)
    
    def create_field_group(self, group):
        """Create a field group"""
        frame = ctk.CTkFrame(self.scrollable_frame, fg_color=colors['card_bg'])
        frame.pack(fill="x", padx=10, pady=8)
        
        # Main field
        self.create_single_field(frame, group['base'], group['label'], group)
        
        # Store dynamic fields info
        if group['add_fields']:
            self.dynamic_fields[group['base']] = {
                'available': group['add_fields'].copy(),
                'added': [],
                'frame': frame
            }
    
    def create_single_field(self, parent, name, label, group):
        """Create a single input field"""
        row_frame = ctk.CTkFrame(parent, fg_color=colors['card_bg'])
        row_frame.pack(fill="x", padx=(0, 10))
        row_frame.grid_columnconfigure(1, weight=1)
        
        # Label
        lbl = ctk.CTkLabel(row_frame,
                          text=label + ":",
                          font=ctk.CTkFont(size=12, weight="bold"),
                          text_color=colors['text'],
                          anchor="w",
                          width=160)
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 0), pady=5)
        
        # Entry
        entry = ctk.CTkEntry(row_frame,
                            font=ctk.CTkFont(family="Consolas", size=12),
                            fg_color=colors['input_bg'],
                            text_color=colors['input_fg'],
                            border_color=colors['border'],
                            border_width=2,
                            corner_radius=6)
        entry.grid(row=0, column=1, sticky="ew", padx=0, pady=5)
        
        self.entries[name] = entry
        
        # Add button for fields with additional options
        if group['add_fields']:
            btn = ctk.CTkButton(row_frame,
                              text="+ Add",
                              command=lambda f=name, g=group: self.add_dynamic_field(f, g),
                              font=ctk.CTkFont(size=11, weight="bold"),
                              width=70,
                              height=30,
                              fg_color=colors['accent'],
                              hover_color='#0284c7',
                              corner_radius=6)
            btn.grid(row=0, column=2, padx=(5, 0), pady=5)
    
    def add_dynamic_field(self, base_field, group, specific_field=None):
        """Add a dynamic field"""
        if specific_field:
            if specific_field not in self.dynamic_fields[base_field]['available']:
                return
            field_name = specific_field
            self.dynamic_fields[base_field]['available'].remove(field_name)
        else:
            if not self.dynamic_fields[base_field]['available']:
                return
            field_name = self.dynamic_fields[base_field]['available'].pop(0)
        
        # Create the dynamic field
        dynamic_frame = ctk.CTkFrame(self.dynamic_fields[base_field]['frame'], 
                                    fg_color=colors['card_bg'])
        dynamic_frame.pack(fill="x", padx=(40, 10), pady=(2, 0))
        dynamic_frame.grid_columnconfigure(1, weight=1)
        
        # Label
        lbl = ctk.CTkLabel(dynamic_frame,
                          text=f"{field_name}:",
                          font=ctk.CTkFont(size=11),
                          text_color=colors['text'],
                          anchor="w",
                          width=115)
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        
        # Entry
        entry = ctk.CTkEntry(dynamic_frame,
                            font=ctk.CTkFont(family="Consolas", size=11),
                            fg_color=colors['input_bg'],
                            text_color=colors['input_fg'],
                            border_color='#475569',
                            border_width=1,
                            corner_radius=4)
        entry.grid(row=0, column=1, sticky="ew", padx=0, pady=2)
        
        # Remove button 
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
        for base_field, data in self.dynamic_fields.items():
            for idx, field_data in enumerate(data['added']):
                if field_data['name'] == field_name:
                    frame.destroy()
                    
                    if field_name in self.entries:
                        del self.entries[field_name]
                    
                    data['added'].pop(idx)
                    data['available'].insert(0, field_name)
                    return
    
    def grid(self, **kwargs):
        """Place the panel in grid"""
        return self.container.grid(**kwargs)
    
    def get_all_parameters(self):
        """Get all parameter values"""
        params = {}
        param_keys = ['e', 'e1', 'e2', 'n', 'n1', 'n2', 'n3', 'c', 'c1', 'c2', 'c3',
                     'p', 'q', 'd', 'dp', 'dq', 'phi']
        
        for key in param_keys:
            value = self.get_value(key)
            if value is not None:
                params[key] = value
        
        return params
    
    def get_value(self, key):
        """Get and convert input value"""
        if key not in self.entries:
            return None
        
        v = self.entries[key].get().strip()
        if not v:
            return None
        
        v = v.replace('\n', '').replace('\r', '').replace(' ', '')
        
        try:
            return int(v, 0)
        except ValueError:
            return None
    
    def get_all_values(self):
        """Get all values as strings"""
        values = {}
        for key, entry in self.entries.items():
            if isinstance(entry, ctk.CTkEntry):
                value = entry.get().strip()
                if value:
                    values[key] = value
        return values
    
    def get_dynamic_state(self):
        """Get dynamic fields state"""
        dynamic_state = {}
        for base_field, data in self.dynamic_fields.items():
            dynamic_state[base_field] = {
                'added': [field_data['name'] for field_data in data['added']],
                'available': data['available'].copy()
            }
        return dynamic_state
    
    def load_values(self, values):
        """Load values from a dictionary (as saved by save_values)"""
        try:
            # First, clear all existing dynamic fields
            for base_field in list(self.dynamic_fields.keys()):
                for field_data in self.dynamic_fields[base_field]['added'][:]:
                    self.remove_dynamic_field(field_data['name'], field_data['frame'])
            
            # Load main field values
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
                            group = None
                            for g in self.get_field_groups():
                                if g['base'] == base_field:
                                    group = g
                                    break
                            
                            if group:
                                # Add the dynamic field
                                self.add_dynamic_field(base_field, group, field_name)
                                
                                # Set its value if it exists
                                if field_name in values and field_name in self.entries:
                                    entry = self.entries[field_name]
                                    if isinstance(entry, ctk.CTkEntry):
                                        entry.delete(0, 'end')
                                        entry.insert(0, values[field_name])
                        
                        # Update available list
                        self.dynamic_fields[base_field]['available'] = state['available']
        
        except Exception as e:
            print(f"Error loading values: {e}")

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
    
    def save_state(self):
        """Save the current state of the input panel"""
        values = {}
        dynamic_state = {}
        
        # Save all entry values
        for key, entry in self.entries.items():
            if isinstance(entry, ctk.CTkEntry):
                value = entry.get().strip()
                if value:
                    values[key] = value
        
        # Save dynamic fields state
        for base_field, data in self.dynamic_fields.items():
            dynamic_state[base_field] = {
                'added': [field_data['name'] for field_data in data['added']],
                'available': data['available'].copy()
            }
        
        values['_dynamic_state'] = dynamic_state
        return values

    def set_cracking_state(self, is_cracking):
        """Update UI state during cracking"""
        if is_cracking:
            self.btn_crack.configure(state="disabled", text="⏳ PROCESSING...")
        else:
            self.btn_crack.configure(state="normal", text="🚀 CRACK RSA")
    
    def clear_all(self):
        """Clear all input fields"""
        for entry in self.entries.values():
            if isinstance(entry, ctk.CTkEntry):
                entry.delete(0, 'end')
        
        # Remove all dynamic fields
        for base_field in list(self.dynamic_fields.keys()):
            for field_data in self.dynamic_fields[base_field]['added'][:]:
                self.remove_dynamic_field(field_data['name'], field_data['frame'])