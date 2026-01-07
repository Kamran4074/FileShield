"""
Main program for FileShield - Kamran's File Encryption System
This is the entry point that provides a simple menu interface
"""

from crypto_engine import encrypt_file, decrypt_file
from file_handler import check_file_exists
import os

def show_menu():
    """Display the main menu options"""
    print("\n" + "="*40)
    print("         FILESHIELD")
    print("    File Encryption System")
    print("="*40)
    print("1. Encrypt a file")
    print("2. Decrypt a file") 
    print("3. List available files")
    print("4. Exit")
    print("="*40)

def main():
    """Main function that runs the program"""
    print("Welcome to FileShield!")
    print("This program helps you encrypt and decrypt files securely.")
    
    while True:
        show_menu()
        choice = input("Choose an option (1-4): ").strip()
        
        if choice == "1":
            # Encrypt a file
            file_path = input("Enter the file path to encrypt: ").strip()
            
            if not check_file_exists(file_path):
                print(f"Error: File '{file_path}' not found!")
                continue
                
            password = input("Enter password for encryption: ").strip()
            
            if len(password) < 4:
                print("Password should be at least 4 characters long!")
                continue
                
            try:
                encrypt_file(file_path, password)
                print(f"✓ File encrypted successfully!")
                print(f"Encrypted file saved as: {file_path}.encrypted")
            except Exception as e:
                print(f"Error encrypting file: {e}")
        
        elif choice == "2":
            # Decrypt a file
            file_path = input("Enter the encrypted file path: ").strip()
            
            if not check_file_exists(file_path):
                print(f"Error: File '{file_path}' not found!")
                continue
                
            password = input("Enter password for decryption: ").strip()
            
            try:
                decrypt_file(file_path, password)
                print(f"✓ File decrypted successfully!")
                decrypted_name = file_path.replace('.encrypted', '_decrypted.txt')
                print(f"Decrypted file saved as: {decrypted_name}")
            except Exception as e:
                print(f"Error decrypting file: {e}")
        
        elif choice == "3":
            # List files in test_files directory
            print("\nAvailable files in test_files/:")
            if os.path.exists("test_files"):
                files = os.listdir("test_files")
                if files:
                    for file in files:
                        print(f"  - test_files/{file}")
                else:
                    print("  No files found in test_files/")
            else:
                print("  test_files/ directory not found")
        
        elif choice == "4":
            print("Thank you for using FileShield!")
            print("Stay secure!")
            break
        
        else:
            print("Invalid choice! Please select 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()