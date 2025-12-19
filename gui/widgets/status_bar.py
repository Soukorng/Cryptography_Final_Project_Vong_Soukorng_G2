"""Status Bar Widget"""

import customtkinter as ctk
from gui.theme import colors

class StatusBar:
    """Status bar at bottom of window"""
    
    def __init__(self, parent):
        self.parent = parent
        self.create_widgets()
    
    def create_widgets(self):
        """Create status bar widgets"""
        self.container = ctk.CTkFrame(self.parent, fg_color=colors['card_bg'], corner_radius=10)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(self.container,
                                        text="Ready",
                                        font=ctk.CTkFont(size=11),
                                        text_color=colors['text'])
        self.status_label.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        
        self.time_label = ctk.CTkLabel(self.container,
                                      text="",
                                      font=ctk.CTkFont(family="Consolas", size=11),
                                      text_color=colors['text'])
        self.time_label.grid(row=0, column=1, sticky="e", padx=20, pady=10)
    
    def grid(self, **kwargs):
        """Place the status bar in grid"""
        return self.container.grid(**kwargs)
    
    def set_status(self, text):
        """Set status text"""
        self.status_label.configure(text=text)
    
    def set_time(self, text):
        """Set time text"""
        self.time_label.configure(text=text)
    
    def update_timer(self, elapsed):
        """Update timer display"""
        m, s = divmod(elapsed, 60)
        h, m = divmod(m, 60)
        
        if h > 0:
            time_str = f"{int(h)}h {int(m)}m {s:.1f}s"
        elif m > 0:
            time_str = f"{int(m)}m {s:.1f}s"
        else:
            time_str = f"{s:.1f}s"
        
        self.container.after(0, self.time_label.configure, {'text': f"Elapsed: {time_str}"})
    
    def clear(self):
        """Clear status bar"""
        self.status_label.configure(text="Ready")
        self.time_label.configure(text="")