"""Results Panel Widget"""

import customtkinter as ctk
from gui.theme import colors

class ResultsPanel:
    """Panel for displaying results"""
    
    def __init__(self, parent):
        self.parent = parent
        self.create_widgets()
    
    def create_widgets(self):
        """Create results panel widgets"""
        self.container = ctk.CTkFrame(self.parent, fg_color=colors['card_bg'], corner_radius=10)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(1, weight=1)
        
        # Header
        header_frame = ctk.CTkFrame(self.container, fg_color=colors['card_bg'])
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(0, weight=1)
        
        title = ctk.CTkLabel(header_frame,
                           text="📊 RESULTS",
                           font=ctk.CTkFont(size=16, weight="bold"),
                           text_color=colors['accent'])
        title.grid(row=0, column=0, sticky="w")
        
        # Action buttons
        actions_frame = ctk.CTkFrame(header_frame, fg_color=colors['card_bg'])
        actions_frame.grid(row=0, column=1, sticky="e")
        
        self.btn_copy = ctk.CTkButton(actions_frame,
                                     text="📋 Copy",
                                     font=ctk.CTkFont(size=12),
                                     width=80,
                                     height=32,
                                     fg_color='#3498db',
                                     hover_color='#2980b9',
                                     corner_radius=8,
                                     state="disabled")
        self.btn_copy.pack(side="left", padx=2)
        
        self.btn_save = ctk.CTkButton(actions_frame,
                                     text="💾 Save",
                                     font=ctk.CTkFont(size=12),
                                     width=80,
                                     height=32,
                                     fg_color='#9b59b6',
                                     hover_color='#8e44ad',
                                     corner_radius=8,
                                     state="disabled")
        self.btn_save.pack(side="left", padx=2)
        
        self.btn_history = ctk.CTkButton(actions_frame,
                                        text="📜 History",
                                        font=ctk.CTkFont(size=12),
                                        width=80,
                                        height=32,
                                        fg_color='#475569',
                                        hover_color='#374151',
                                        corner_radius=8)
        self.btn_history.pack(side="left", padx=2)
        
        # Results text area
        text_frame = ctk.CTkFrame(self.container, fg_color=colors['card_bg'])
        text_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        text_frame.grid_columnconfigure(0, weight=1)
        text_frame.grid_rowconfigure(0, weight=1)
        
        self.results_text = ctk.CTkTextbox(text_frame,
                                          font=ctk.CTkFont(family="Consolas", size=12),
                                          fg_color=colors['input_bg'],
                                          text_color=colors['input_fg'],
                                          corner_radius=8)
        self.results_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure text tags
        self.configure_text_tags()
    
    def configure_text_tags(self):
        """Configure text color tags"""
        tags = {
            "success": colors['success'],
            "error": colors['error'],
            "warning": colors['warning'],
            "flag": colors['accent'],
            "header": colors['accent'],
            "param": '#94a3b8',
            "ascii_red": '#ff6b6b',
            "history_result": '#f8a5c2',
        }
        
        for tag, color in tags.items():
            self.results_text.tag_config(tag, foreground=color)
    
    def grid(self, **kwargs):
        """Place the panel in grid"""
        return self.container.grid(**kwargs)
    
    def clear_results(self):
        """Clear results text"""
        self.results_text.delete("1.0", "end")
        self.btn_copy.configure(state="disabled")
        self.btn_save.configure(state="disabled")
    
    def get_results(self):
        """Get results text"""
        return self.results_text.get("1.0", "end").strip()