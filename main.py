import sys
from PyQt5.QtWidgets import QApplication
from gui import FileEncryptorGUI

def main():
    app = QApplication(sys.argv)
    
    # Set application information
    app.setApplicationName("Secure File Encryptor/Decryptor")
    app.setApplicationDisplayName("🔒 Secure File Encryptor/Decryptor 🛡️")
    app.setApplicationVersion("1.0.0")
    
    window = FileEncryptorGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()