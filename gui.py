import os
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox, 
                             QProgressBar, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from qt_material import apply_stylesheet
from encryptor import FileEncryptor

class WorkerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, operation, input_path, output_path, password):
        super().__init__()
        self.operation = operation  # 'encrypt' or 'decrypt'
        self.input_path = input_path
        self.output_path = output_path
        self.password = password

    def run(self):
        try:
            if self.operation == 'encrypt':
                FileEncryptor.encrypt_file(self.input_path, self.output_path, self.password)
            else:
                success = FileEncryptor.decrypt_file(self.input_path, self.output_path, self.password)
                if not success:
                    raise Exception("Decryption failed - possibly wrong password or corrupted file")
            
            self.finished.emit(True, "")
        except Exception as e:
            self.error.emit(str(e))

class FileEncryptorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔒 Secure File Encryptor/Decryptor 🛡️")
        self.setGeometry(100, 100, 600, 400)
        
        self.init_ui()
        self.setup_connections()
        
        # Dark theme
        apply_stylesheet(self, theme='dark_teal.xml')

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # File Selection
        self.file_group = QGroupBox("File Operations")
        file_layout = QVBoxLayout()
        
        self.input_label = QLabel("No file selected")
        self.input_label.setWordWrap(True)
        self.btn_select_file = QPushButton("Select File")
        self.btn_select_encrypted = QPushButton("Select Encrypted File")
        
        file_btn_layout = QHBoxLayout()
        file_btn_layout.addWidget(self.btn_select_file)
        file_btn_layout.addWidget(self.btn_select_encrypted)
        
        self.output_label = QLabel("Output path: Not set")
        self.btn_select_output = QPushButton("Set Output Path")
        
        file_layout.addWidget(self.input_label)
        file_layout.addLayout(file_btn_layout)
        file_layout.addWidget(self.output_label)
        file_layout.addWidget(self.btn_select_output)
        self.file_group.setLayout(file_layout)
        
        # Password
        self.password_group = QGroupBox("Security")
        password_layout = QVBoxLayout()
        
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter password")
        self.password_edit.setEchoMode(QLineEdit.Password)
        
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText("Confirm password")
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        
        password_layout.addWidget(self.password_edit)
        password_layout.addWidget(self.confirm_edit)
        self.password_group.setLayout(password_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Buttons
        self.btn_encrypt = QPushButton("Start Encryption")
        self.btn_decrypt = QPushButton("Start Decryption")
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_encrypt)
        btn_layout.addWidget(self.btn_decrypt)
        
        # Add all to main layout
        layout.addWidget(self.file_group)
        layout.addWidget(self.password_group)
        layout.addWidget(self.progress_bar)
        layout.addLayout(btn_layout)
        
        # Disable buttons initially
        self.btn_encrypt.setEnabled(False)
        self.btn_decrypt.setEnabled(False)
        
        # Status
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def setup_connections(self):
        self.btn_select_file.clicked.connect(lambda: self.select_file(encrypted=False))
        self.btn_select_encrypted.clicked.connect(lambda: self.select_file(encrypted=True))
        self.btn_select_output.clicked.connect(self.select_output_path)
        self.btn_encrypt.clicked.connect(self.start_encryption)
        self.btn_decrypt.clicked.connect(self.start_decryption)
        
        # Enable/disable buttons based on input
        self.password_edit.textChanged.connect(self.check_inputs)
        self.confirm_edit.textChanged.connect(self.check_inputs)

    def select_file(self, encrypted=False):
        if encrypted:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File", "", "Encrypted Files (*.encrypted);;All Files (*)")
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
            
        if file_path:
            self.input_path = file_path
            self.input_label.setText(f"Selected file: {file_path}")
            
            # Set default output path
            dir_path, file_name = os.path.split(file_path)
            if encrypted:
                output_name = file_name.replace('.encrypted', '') if file_name.endswith('.encrypted') else file_name + '.decrypted'
            else:
                output_name = file_name + '.encrypted'
            self.output_path = os.path.join(dir_path, output_name)
            self.output_label.setText(f"Output path: {self.output_path}")
            
            self.check_inputs()

    def select_output_path(self):
        if hasattr(self, 'input_path'):
            dir_path, file_name = os.path.split(self.input_path)
            default_path = os.path.join(dir_path, file_name + '.encrypted')
            
            output_path, _ = QFileDialog.getSaveFileName(self, "Set Output Path", default_path, "All Files (*)")
            
            if output_path:
                self.output_path = output_path
                self.output_label.setText(f"Output path: {output_path}")
                self.check_inputs()

    def check_inputs(self):
        has_file = hasattr(self, 'input_path') and hasattr(self, 'output_path')
        passwords_match = self.password_edit.text() == self.confirm_edit.text()
        password_valid = len(self.password_edit.text()) >= 8
        
        self.btn_encrypt.setEnabled(has_file and passwords_match and password_valid)
        self.btn_decrypt.setEnabled(has_file and password_valid)
        
        if not passwords_match and self.confirm_edit.text():
            self.status_label.setText("Passwords do not match!")
            self.status_label.setStyleSheet("color: red;")
        elif not password_valid and self.password_edit.text():
            self.status_label.setText("Password must be at least 8 characters!")
            self.status_label.setStyleSheet("color: red;")
        else:
            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("color: green;")

    def start_encryption(self):
        self.run_operation('encrypt')

    def start_decryption(self):
        self.run_operation('decrypt')

    def run_operation(self, operation):
        if not hasattr(self, 'input_path') or not hasattr(self, 'output_path'):
            QMessageBox.warning(self, "Error", "Please select input and output paths first!")
            return
            
        if operation == 'encrypt' and self.password_edit.text() != self.confirm_edit.text():
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
            
        if os.path.exists(self.output_path):
            reply = QMessageBox.question(
                self, 'File Exists',
                f"The output file '{self.output_path}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        # Disable UI during operation
        self.set_ui_enabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"{operation.capitalize()}ing file...")
        self.status_label.setStyleSheet("color: orange;")
        
        # Create and start worker thread
        self.worker = WorkerThread(
            operation, 
            self.input_path, 
            self.output_path, 
            self.password_edit.text()
        )
        self.worker.finished.connect(self.operation_finished)
        self.worker.error.connect(self.operation_error)
        self.worker.start()

    def set_ui_enabled(self, enabled):
        self.btn_select_file.setEnabled(enabled)
        self.btn_select_encrypted.setEnabled(enabled)
        self.btn_select_output.setEnabled(enabled)
        self.password_edit.setEnabled(enabled)
        self.confirm_edit.setEnabled(enabled)
        self.btn_encrypt.setEnabled(enabled)
        self.btn_decrypt.setEnabled(enabled)

    def operation_finished(self, success, message):
        self.set_ui_enabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText("Operation completed successfully!")
        self.status_label.setStyleSheet("color: green;")
        QMessageBox.information(self, "Success", "Operation completed successfully!")

    def operation_error(self, error_message):
        self.set_ui_enabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Error: {error_message}")
        self.status_label.setStyleSheet("color: red;")
        QMessageBox.critical(self, "Error", f"Operation failed:\n{error_message}")