import os
import sys

# Add the project root to Python path (so imports work)
sys.path.append(os.path.dirname(__file__))

# Now launch the real GUI
from gui.app import RSACracker
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    app = RSACracker(root)
    root.mainloop()
