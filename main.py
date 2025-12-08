# main.py
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.app import RSACracker
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    app = RSACracker(root)
    root.mainloop()