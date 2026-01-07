"""
GUI Frontend for FileShield - Kamran's File Encryption System
Beautiful and user-friendly interface using tkinter
Developer: Kamran
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from crypto_engine import encrypt_file, decrypt_file
from file_handler import check_file_exists

class CyberSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("🔒 FileShield - Kamran's File Encryption Tool")
        self.root.geometry("600x500")
        self.root.configure(bg='#1e1e2e')
        
        # Center the window
        self.root.eval('tk::PlaceWindow . center')
        
    def create_widgets(self):
        """Create all GUI elements"""
        
        # Title Frame
        title_frame = tk.Frame(self.root, bg='#1e1e2e')
        title_frame.pack(pady=20)
        
        title_label = tk.Label(
            title_frame,
            text="🔒 FILESHIELD - ADVANCED FILE ENCRYPTION 🔒",
            font=('Arial', 18, 'bold'),
            fg='#00ff88',
            bg='#1e1e2e'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Advanced File Encryption System",
            font=('Arial', 10),
            fg='#888888',
            bg='#1e1e2e'
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Main Content Frame
        main_frame = tk.Frame(self.root, bg='#1e1e2e')
        main_frame.pack(expand=True, fill='both', padx=40, pady=20)
        
        # File Selection Frame
        file_frame = tk.LabelFrame(
            main_frame,
            text="Select File",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#2d2d44',
            bd=2
        )
        file_frame.pack(fill='x', pady=(0, 20))
        
        # File path display
        self.file_path_var = tk.StringVar()
        self.file_path_var.set("No file selected")
        
        file_path_label = tk.Label(
            file_frame,
            textvariable=self.file_path_var,
            font=('Arial', 10),
            fg='#ffffff',
            bg='#2d2d44',
            wraplength=500
        )
        file_path_label.pack(pady=10, padx=10)
        
        # Browse button
        browse_btn = tk.Button(
            file_frame,
            text="Browse Files",
            command=self.browse_file,
            font=('Arial', 11, 'bold'),
            bg='#4a4a6a',
            fg='white',
            activebackground='#5a5a7a',
            relief='flat',
            padx=20,
            pady=8
        )
        browse_btn.pack(pady=(0, 15))
        
        # Password Frame
        password_frame = tk.LabelFrame(
            main_frame,
            text="Enter Password",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#2d2d44',
            bd=2
        )
        password_frame.pack(fill='x', pady=(0, 20))
        
        # Password input container
        password_container = tk.Frame(password_frame, bg='#2d2d44')
        password_container.pack(pady=15, padx=20, fill='x')
        
        self.password_var = tk.StringVar()
        self.password_visible = False
        
        self.password_entry = tk.Entry(
            password_container,
            textvariable=self.password_var,
            font=('Arial', 12),
            show='*',
            bg='#3d3d5d',
            fg='white',
            insertbackground='white',
            relief='flat',
            bd=10
        )
        self.password_entry.pack(side='left', fill='x', expand=True)
        
        # Eye button to show/hide password
        self.eye_btn = tk.Button(
            password_container,
            text="Show",
            command=self.toggle_password_visibility,
            font=('Arial', 12),
            bg='#4a4a6a',
            fg='white',
            activebackground='#5a5a7a',
            relief='flat',
            width=3,
            pady=8
        )
        self.eye_btn.pack(side='right', padx=(5, 0))
        
        # Buttons Frame
        buttons_frame = tk.Frame(main_frame, bg='#1e1e2e')
        buttons_frame.pack(fill='x', pady=20)
        
        # Encrypt Button
        encrypt_btn = tk.Button(
            buttons_frame,
            text="🔒 ENCRYPT FILE",
            command=self.encrypt_file,
            font=('Arial', 12, 'bold'),
            bg='#ff6b6b',
            fg='white',
            activebackground='#ff5252',
            relief='flat',
            padx=30,
            pady=12
        )
        encrypt_btn.pack(side='left', expand=True, fill='x', padx=(0, 10))
        
        # Decrypt Button
        decrypt_btn = tk.Button(
            buttons_frame,
            text="🔓 DECRYPT FILE",
            command=self.decrypt_file,
            font=('Arial', 12, 'bold'),
            bg='#4ecdc4',
            fg='white',
            activebackground='#26a69a',
            relief='flat',
            padx=30,
            pady=12
        )
        decrypt_btn.pack(side='right', expand=True, fill='x', padx=(10, 0))
        
        # File Content Display Frame
        content_frame = tk.LabelFrame(
            main_frame,
            text="File Content Preview",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#2d2d44',
            bd=2
        )
        content_frame.pack(fill='both', expand=True, pady=(20, 0))
        
        # Create scrollable text area
        text_container = tk.Frame(content_frame, bg='#2d2d44')
        text_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Text widget with scrollbar
        self.content_text = tk.Text(
            text_container,
            font=('Consolas', 10),
            bg='#1a1a2e',
            fg='#ffffff',
            insertbackground='white',
            relief='flat',
            wrap='word',
            height=8,
            state='disabled'  # Read-only by default
        )
        
        # Scrollbar for text area
        scrollbar = tk.Scrollbar(text_container, orient='vertical', command=self.content_text.yview)
        self.content_text.configure(yscrollcommand=scrollbar.set)
        
        # Pack text and scrollbar
        self.content_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Buttons for content actions
        content_buttons_frame = tk.Frame(content_frame, bg='#2d2d44')
        content_buttons_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        view_original_btn = tk.Button(
            content_buttons_frame,
            text="View Original File",
            command=self.view_original_content,
            font=('Arial', 9),
            bg='#74b9ff',
            fg='white',
            activebackground='#0984e3',
            relief='flat',
            padx=15,
            pady=5
        )
        view_original_btn.pack(side='left', padx=(0, 5))
        
        view_encrypted_btn = tk.Button(
            content_buttons_frame,
            text="View Encrypted File",
            command=self.view_encrypted_content,
            font=('Arial', 9),
            bg='#fd79a8',
            fg='white',
            activebackground='#e84393',
            relief='flat',
            padx=15,
            pady=5
        )
        view_encrypted_btn.pack(side='left', padx=5)
        
        clear_btn = tk.Button(
            content_buttons_frame,
            text="Clear",
            command=self.clear_content,
            font=('Arial', 9),
            bg='#636e72',
            fg='white',
            activebackground='#2d3436',
            relief='flat',
            padx=15,
            pady=5
        )
        clear_btn.pack(side='right')
        
        # Status Frame
        status_frame = tk.Frame(main_frame, bg='#1e1e2e')
        status_frame.pack(fill='x', pady=(10, 0))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to encrypt/decrypt files")
        
        status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            font=('Arial', 10),
            fg='#888888',
            bg='#1e1e2e'
        )
        status_label.pack()
        
        # Demo Files Button
        demo_btn = tk.Button(
            main_frame,
            text="View Available Files",
            command=self.show_demo_files,
            font=('Arial', 10),
            bg='#6c5ce7',
            fg='white',
            activebackground='#5f3dc4',
            relief='flat',
            padx=20,
            pady=8
        )
        demo_btn.pack(pady=(5, 0))
        
        # Initialize content display
        self.clear_content()
        
    def update_content_display(self, content, title="File Content"):
        """Update the content display area"""
        self.content_text.config(state='normal')
        self.content_text.delete(1.0, tk.END)
        
        # Add title
        self.content_text.insert(tk.END, f"=== {title} ===\n\n", 'title')
        
        # Add content
        if isinstance(content, bytes):
            # For encrypted content, show first 200 bytes in hex format
            hex_content = content[:200].hex()
            formatted_hex = ' '.join([hex_content[i:i+2] for i in range(0, len(hex_content), 2)])
            self.content_text.insert(tk.END, "ENCRYPTED DATA (First 200 bytes in hexadecimal):\n\n")
            self.content_text.insert(tk.END, formatted_hex)
            if len(content) > 200:
                self.content_text.insert(tk.END, f"\n\n... and {len(content) - 200} more bytes")
            self.content_text.insert(tk.END, "\n\nThis scrambled data is unreadable without the correct password!")
        else:
            # For text content
            self.content_text.insert(tk.END, content)
        
        self.content_text.config(state='disabled')
    
    def view_original_content(self):
        """View the content of the selected original file"""
        file_path = self.file_path_var.get()
        
        print(f"\n👀 Viewing original file content: {file_path}")
        
        if file_path == "No file selected":
            print("No file selected for viewing")
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        # If it's an encrypted file, try to find the original
        if file_path.endswith('.encrypted'):
            original_path = file_path.replace('.encrypted', '')
            if check_file_exists(original_path):
                file_path = original_path
                print(f"Found original file: {original_path}")
            else:
                print("Original file not found")
                messagebox.showwarning("Original Not Found", "Original file not found. Try selecting the unencrypted file.")
                return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"Successfully loaded {len(content)} characters from file")
            self.update_content_display(content, f"Original File: {os.path.basename(file_path)}")
            self.status_var.set(f"Showing original content of {os.path.basename(file_path)}")
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            messagebox.showerror("Error", f"Could not read file:\n{str(e)}")
    
    def view_encrypted_content(self):
        """View the content of the encrypted file"""
        file_path = self.file_path_var.get()
        
        if file_path == "No file selected":
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        # If it's not an encrypted file, try to find the encrypted version
        if not file_path.endswith('.encrypted'):
            encrypted_path = file_path + '.encrypted'
            if check_file_exists(encrypted_path):
                file_path = encrypted_path
            else:
                messagebox.showwarning("Encrypted Not Found", "Encrypted file not found. Please encrypt the file first.")
                return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            self.update_content_display(content, f"🔒 Encrypted File: {os.path.basename(file_path)}")
            self.status_var.set(f"Showing encrypted content of {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not read encrypted file:\n{str(e)}")
    
    def clear_content(self):
        """Clear the content display area"""
        self.content_text.config(state='normal')
        self.content_text.delete(1.0, tk.END)
        self.content_text.insert(tk.END, "Content preview area\n\nSelect a file and click 'View Original File' or 'View Encrypted File' to see the content here.")
        self.content_text.config(state='disabled')
        self.status_var.set("Content display cleared")
    
    def toggle_password_visibility(self):
        """Toggle password visibility (show/hide)"""
        if self.password_visible:
            # Hide password
            self.password_entry.config(show='*')
            self.eye_btn.config(text="Show")
            self.password_visible = False
        else:
            # Show password
            self.password_entry.config(show='')
            self.eye_btn.config(text="Hide")
            self.password_visible = True
    
    def browse_file(self):
        """Open file browser to select a file"""
        print("\n📂 Opening file browser...")
        
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Encrypted files", "*.encrypted"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            print(f"File selected: {file_path}")
            print(f"File size: {os.path.getsize(file_path)} bytes")
            self.file_path_var.set(file_path)
            self.status_var.set(f"Selected: {os.path.basename(file_path)}")
        else:
            print("No file selected")
    
    def encrypt_file(self):
        """Encrypt the selected file"""
        file_path = self.file_path_var.get()
        password = self.password_var.get()
        
        # Terminal logging
        print("\n" + "="*60)
        print("ENCRYPTION PROCESS STARTED")
        print("="*60)
        print(f"Selected File: {file_path}")
        print(f"Password Length: {len(password)} characters")
        
        # Validation
        if file_path == "No file selected":
            print("ERROR: No file selected!")
            messagebox.showerror("Error", "Please select a file first!")
            return
            
        if not password:
            print("ERROR: No password provided!")
            messagebox.showerror("Error", "Please enter a password!")
            return
            
        if len(password) < 4:
            print("ERROR: Password too short!")
            messagebox.showerror("Error", "Password must be at least 4 characters!")
            return
            
        if not check_file_exists(file_path):
            print("ERROR: File not found!")
            messagebox.showerror("Error", "Selected file not found!")
            return
        
        try:
            # Show processing
            print("Processing encryption...")
            print(f"Original file size: {os.path.getsize(file_path)} bytes")
            self.status_var.set("Encrypting file...")
            self.root.update()
            
            # Encrypt file
            print("Generating encryption key from password...")
            print("Encrypting file content...")
            encrypt_file(file_path, password)
            
            # Show encrypted content automatically
            encrypted_path = file_path + ".encrypted"
            if check_file_exists(encrypted_path):
                encrypted_size = os.path.getsize(encrypted_path)
                print(f"Encrypted file size: {encrypted_size} bytes")
                print(f"Encrypted file saved: {os.path.basename(encrypted_path)}")
                
                with open(encrypted_path, 'rb') as f:
                    encrypted_content = f.read()
                self.update_content_display(encrypted_content, f"🔒 Encrypted: {os.path.basename(encrypted_path)}")
            
            # Success message
            print("ENCRYPTION COMPLETED SUCCESSFULLY!")
            print("🔒 File is now secure and unreadable without password")
            print("="*60)
            
            messagebox.showinfo(
                "Success!", 
                f"File encrypted successfully!\n\nEncrypted file saved as:\n{os.path.basename(encrypted_path)}"
            )
            
            self.status_var.set("File encrypted successfully!")
            self.password_var.set("")  # Clear password
            
        except Exception as e:
            print(f"ENCRYPTION FAILED: {str(e)}")
            print("="*60)
            messagebox.showerror("Encryption Error", f"Failed to encrypt file:\n{str(e)}")
            self.status_var.set("Encryption failed!")
    
    def decrypt_file(self):
        """Decrypt the selected file"""
        file_path = self.file_path_var.get()
        password = self.password_var.get()
        
        # Terminal logging
        print("\n" + "="*60)
        print("DECRYPTION PROCESS STARTED")
        print("="*60)
        print(f"Selected File: {file_path}")
        print(f"Password Length: {len(password)} characters")
        
        # Validation
        if file_path == "No file selected":
            print("ERROR: No encrypted file selected!")
            messagebox.showerror("Error", "Please select an encrypted file first!")
            return
            
        if not password:
            print("ERROR: No password provided!")
            messagebox.showerror("Error", "Please enter the decryption password!")
            return
            
        if not check_file_exists(file_path):
            print("ERROR: Encrypted file not found!")
            messagebox.showerror("Error", "Selected file not found!")
            return
        
        try:
            # Show processing
            print("Processing decryption...")
            print(f"Encrypted file size: {os.path.getsize(file_path)} bytes")
            self.status_var.set("Decrypting file...")
            self.root.update()
            
            # Decrypt file
            print("Verifying password and extracting salt...")
            print("Decrypting file content...")
            decrypt_file(file_path, password)
            
            # Show decrypted content automatically
            decrypted_name = file_path.replace('.encrypted', '_decrypted.txt')
            if check_file_exists(decrypted_name):
                decrypted_size = os.path.getsize(decrypted_name)
                print(f"Decrypted file size: {decrypted_size} bytes")
                print(f"Decrypted file saved: {os.path.basename(decrypted_name)}")
                
                with open(decrypted_name, 'r', encoding='utf-8') as f:
                    decrypted_content = f.read()
                self.update_content_display(decrypted_content, f"🔓 Decrypted: {os.path.basename(decrypted_name)}")
            
            # Success message
            print("DECRYPTION COMPLETED SUCCESSFULLY!")
            print("🔓 File is now readable and restored to original format")
            print("="*60)
            
            messagebox.showinfo(
                "Success!", 
                f"File decrypted successfully!\n\nDecrypted file saved as:\n{os.path.basename(decrypted_name)}"
            )
            
            self.status_var.set("File decrypted successfully!")
            self.password_var.set("")  # Clear password
            
        except Exception as e:
            print(f"DECRYPTION FAILED: {str(e)}")
            print("TIP: Make sure you're using the correct password")
            print("="*60)
            messagebox.showerror("Decryption Error", f"Failed to decrypt file:\n{str(e)}")
            self.status_var.set("Decryption failed!")
    
    def show_demo_files(self):
        """Show available files for encryption/decryption"""
        demo_files = []
        if os.path.exists("test_files"):
            files = os.listdir("test_files")
            demo_files = [f"test_files/{f}" for f in files if os.path.isfile(f"test_files/{f}")]
        
        if demo_files:
            file_list = "\n".join([f"• {os.path.basename(f)}" for f in demo_files])
            messagebox.showinfo("Available Files", f"Available files for encryption:\n\n{file_list}")
        else:
            messagebox.showinfo("Available Files", "No files found in test_files/ directory")

def main():
    """Run the GUI application"""
    print("STARTING FILESHIELD - FILE ENCRYPTION SYSTEM")
    print("="*60)
    print("FileShield - Advanced File Encryption")
    print("Developer: Kamran")
    print("Language: Python")
    print("Interface: Tkinter GUI")
    print("="*60)
    print("Starting GUI interface...")
    
    root = tk.Tk()
    app = CyberSecurityGUI(root)
    
    print("GUI successfully launched!")
    print("-" * 60)
    
    root.mainloop()
    
    print("\nFileShield closed. Thank you for using FileShield!")

if __name__ == "__main__":
    main()