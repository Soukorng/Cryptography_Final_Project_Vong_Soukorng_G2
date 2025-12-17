import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.app import RSACracker
import customtkinter as ctk

def main():
    """Main entry point"""
    root = ctk.CTk()
    app = RSACracker(root)
    root.mainloop()

if __name__ == "__main__":
    main()