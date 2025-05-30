
# 🔒 VaultEncryptor - Secure File Encryption Tool 🛡️

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

A military-grade file encryption/decryption tool with GUI, featuring AES-256-GCM encryption and secure key derivation.

## 🌟 Features

### 🔐 Security
- **AES-256-GCM** encryption (NSA-approved standard)
- **PBKDF2-HMAC-SHA256** with 600,000 iterations
- **Tamper-proofing** through authentication tags
- **Cryptographically secure** random number generation

### 🖥️ User Experience
- Modern dark-mode GUI (PyQt5)
- Progress tracking for large files
- Intuitive operation workflow
- Comprehensive error handling

### ⚙️ Technical
- Chunked processing (supports files >10GB)
- Memory-efficient streaming
- Automatic cleanup on failures
- Cross-platform compatibility

## 📦 Installation

### Prerequisites
- Python 3.6+ (Recommended: 3.8+)

### Quick Start
```bash
# Clone repository
git clone https://github.com/Kirankumarvel/VaultEncryptor.git
cd VaultEncryptor

# Install dependencies
pip install -r requirements.txt

# Launch application
python main.py
```

### Requirements
```bash
PyQt5==5.15.9
cryptography==41.0.4
qt_material==2.14
```

## 🛠️ Usage Guide

### 🔒 Encrypting Files
1. Click **"Select File"**
2. Set output path (default: `.encrypted` extension)
3. Enter password + confirmation
4. Click **"Start Encryption"**
5. Wait for completion (progress bar will update)

### 🔓 Decrypting Files
1. Click **"Select Encrypted File"**
2. Set output path (original filename suggested)
3. Enter original password
4. Click **"Start Decryption"**
5. Retrieve your original file

![GUI Screenshot](![image](https://github.com/user-attachments/assets/50dfa266-840e-49f7-a834-454e8f522bbe)
) 

## ⚠️ Security Notes
- **Passwords cannot be recovered** - Store them securely
- Encrypted files contain **salt+nonce** in header
- Each encryption generates **unique random salts**
- GCM authentication **prevents tampering**

## ⚙️ Technical Specifications

| Component          | Specification                          |
|--------------------|---------------------------------------|
| Encryption         | AES-256-GCM                           |
| Key Derivation     | PBKDF2-HMAC-SHA256 (600k iterations)  |
| Salt Size          | 16 bytes                              |
| Nonce Size         | 12 bytes                              |
| Chunk Size         | 1 MB (optimal performance)            |
| Authentication Tag | 16 bytes (built into GCM)             |

## 📚 Documentation

### File Format
```
[SALT:16][NONCE:12][ENCRYPTED_CHUNKS...]
```

### Development API
```python
from encryptor import FileEncryptor

# Encrypt
FileEncryptor.encrypt_file("input.txt", "output.enc", "securepassword")

# Decrypt 
FileEncryptor.decrypt_file("output.enc", "decrypted.txt", "securepassword")
```

## 🚀 Performance Tips
- For **large files**: Ensure sufficient disk space
- **SSD storage** recommended for multi-GB files
- Close other memory-intensive applications

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

## 📧 Contact
Kiran Kumar - [Topmate](https://topmate.io/kirankumar_v)
Project Link: [https://github.com/Kirankumarvel/VaultEncryptor](https://github.com/Kirankumarvel/VaultEncryptor)
