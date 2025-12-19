# Cryptography_Final_Project_Vong_Soukorng_G2
# RSA CRACKER TOOL

## Version
**v1.0.0 - Final Version of RSA CRACKER TOOL**

---

## Project Overview
The **RSA Cracker Tool** is an advanced, user-friendly application designed for CTF (Capture The Flag), cryptography education. This tool provides a comprehensive suite of RSA cryptanalysis techniques through a User-friendly graphical interface, making complex mathematical attacks accessible to both beginners and security professionals.

---

## Key Features
- Modern User-Friendly GUI
- 11+ RSA Crack Methods
- Automatically Crack Challenges
- Multi-Format Support
- Smart Factorization
- Real-Time Results
- Dynamic Field Management
- Save/Load Functionality
- Reset, Copy, History Functionality
- Cross-Platform

---

## Supported RSA Attacks
- Low Exponent Attack (Small e)
- Wiener’s Attack (Small d)
- Håstad’s Broadcast Attack
- Common Modulus Attack
- Double Encryption with same n
- Even Modulus Attack
- Massive RSA Attack (Prime Modulus Attack)
- Partial Key Decryption
- CRT-based Decryption
- φ(n)-based Decryption
- Standard Decryption
- Smart Hybrid Factorization

---

## Installation/Setup
### 1. Clone the repository
```bash
git clone https://github.com/Soukorng/Cryptography_Final_Project_Vong_Soukorng_G2.git
cd Cryptography_Final_Project_Vong_Soukorng_G2
```

### 2. Create virtual environment 
```bash
# On Windows: 
python -m venv venv
venv\Scripts\activate

# On Linux/Mac:
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt

```

## Usage Examples
### 1. Run the application
```bash
python main.py
```

- Left Panel: Input RSA parameters (e, n, c, p, q, d, φ, etc) 
- Click "CRACK RSA": Tool runs all applicable cracks method in priority order
- Click "Reset": Erase all input and results
- Click "Save Values": Saved all input and load it back when reopen tool

- Right Panel: View results in multiple formats (ASCII, HEX, Decimal, Bytes)
- Click "Copy": Copied all the results display to clipboard
- Click "Save": Save all the results display into a file
- Click "History": Display the last 10 successful cracked results

---

## Project Structure
Cryptography_Final_Project_Vong_Soukorng_G2/
├── rsa_core/                         # Core RSA functionality
│   ├── attacks/                      # Attack implementations
│   │   ├── low_exponent.py           # Small e attacks
│   │   ├── wiener.py                 # Small d attack
│   │   ├── broadcast.py              # Håstad attack
│   │   ├── double_encryption.py      # Same n, two e's
│   │   ├── common_modulus.py         # Same n, same m, two e's
│   │   ├── even_n.py                 # n is even
│   │   └── massive_rsa.py            # n is prime
│   ├── decryption/                   # Decryption strategies
│   │   ├── standard.py               # Basic RSA decryption
│   │   ├── crt.py                    # Chinese Remainder Theorem decryption
│   │   ├── with_phi.py               # Decrypt using φ(n)
│   │   ├── with_pq.py                # Decrypt using p and q
│   │   └── partial_key.py            # Decrypt with partial key
│   ├── factorization/                # Factorization algorithms
│   │   ├── core.py                   # Pollard Rho algorithms
│   │   ├── ecm.py                    # Elliptic Curve Method
│   │   ├── factordb.py               # FactorDB API integration
│   │   └── smart_factor.py           # Auto-factorization engine
│   └── utils/                        # Utility functions
│       ├── converters.py             # Data conversion
│       ├── math_utils.py             # Extended GCD, mod inverse
│       ├── validation.py             # Parameter validation
│       └── helpers.py                # Attack helper functions
├── gui/                              # GUI application
│   ├── main_window.py                # Main application window
│   ├── widgets/                      # Reusable GUI components
│   │   ├── input_panel.py            # Parameter input panel
│   │   ├── results_panel.py          # Results display panel
│   │   └── status_bar.py             # Status bar
│   └── theme.py                      # Color scheme
├── main.py                           # Application entry point
├── requirements.txt                  # Python dependencies
└── README.md                         # This file

---

## Dependencies
gmpy2>=2.2.0              # Fast large integer arithmetic
factordb-python>=1.0.0    # FactorDB online factorization API
customtkinter>=5.2.2      # Modern GUI framework

---

## Author
Vong Soukorng
Cybersecurity Specialization
Final Cryptography Project

---