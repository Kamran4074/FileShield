"""
Crypto Engine - Handles encryption and decryption operations
This module contains the core cryptographic functions
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def generate_key_from_password(password, salt):
    """
    Generate an encryption key from a password
    
    Args:
        password (str): User's password
        salt (bytes): Random salt for security
    
    Returns:
        bytes: Encryption key
    """
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Create key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Makes it harder for attackers to crack
    )
    
    # Generate key and encode it properly for Fernet
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def encrypt_file(file_path, password):
    """
    Encrypt a file using the provided password
    
    Args:
        file_path (str): Path to the file to encrypt
        password (str): Password for encryption
    """
    # Generate a random salt (different each time for security)
    salt = os.urandom(16)
    
    # Create encryption key from password
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    
    # Read the original file
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Encrypt the data
    encrypted_data = fernet.encrypt(file_data)
    
    # Save encrypted file with salt at the beginning
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        # Write salt first (needed for decryption)
        encrypted_file.write(salt)
        # Then write encrypted data
        encrypted_file.write(encrypted_data)
    
    print(f"Encryption complete!")

def decrypt_file(encrypted_file_path, password):
    """
    Decrypt a file using the provided password
    
    Args:
        encrypted_file_path (str): Path to the encrypted file
        password (str): Password for decryption
    """
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        # Read salt (first 16 bytes)
        salt = encrypted_file.read(16)
        # Read encrypted data (rest of the file)
        encrypted_data = encrypted_file.read()
    
    # Generate the same key using password and salt
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    
    try:
        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Save decrypted file
        decrypted_file_path = encrypted_file_path.replace('.encrypted', '_decrypted.txt')
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        print(f"Decryption complete!")
        
    except Exception as e:
        raise Exception("Decryption failed! Wrong password or corrupted file.")

def demo_encryption():
    """
    Simple demonstration of how encryption works
    """
    print("\n--- ENCRYPTION DEMO ---")
    
    # Sample text
    original_text = "This is a secret message!"
    print(f"Original text: {original_text}")
    
    # Convert to bytes
    text_bytes = original_text.encode('utf-8')
    
    # Generate a simple key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    
    # Encrypt
    encrypted_text = fernet.encrypt(text_bytes)
    print(f"Encrypted: {encrypted_text}")
    
    # Decrypt
    decrypted_text = fernet.decrypt(encrypted_text).decode('utf-8')
    print(f"Decrypted: {decrypted_text}")
    
    print("--- END DEMO ---\n")