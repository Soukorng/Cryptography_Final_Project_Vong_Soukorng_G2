#!/usr/bin/env python3
"""
RSA CRACKER TOOL - Main Entry Point
"""

import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import RSACracker
import customtkinter as ctk

def main():
    """Main entry point"""
    try:
        root = ctk.CTk()
        app = RSACracker(root)
        root.mainloop()
    except Exception as e:
        print(f"Error starting application: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()