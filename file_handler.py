"""
File Handler - Manages file operations
This module handles reading, writing, and checking files
"""

import os

def check_file_exists(file_path):
    """
    Check if a file exists
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        bool: True if file exists, False otherwise
    """
    return os.path.exists(file_path) and os.path.isfile(file_path)

def read_text_file(file_path):
    """
    Read content from a text file
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        str: Content of the file
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        raise Exception(f"Error reading file: {e}")

def write_text_file(file_path, content):
    """
    Write content to a text file
    
    Args:
        file_path (str): Path to the file
        content (str): Content to write
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
    except Exception as e:
        raise Exception(f"Error writing file: {e}")

def get_file_size(file_path):
    """
    Get the size of a file in bytes
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        int: File size in bytes
    """
    if check_file_exists(file_path):
        return os.path.getsize(file_path)
    return 0

def create_directory(dir_path):
    """
    Create a directory if it doesn't exist
    
    Args:
        dir_path (str): Path to the directory
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        print(f"Created directory: {dir_path}")

def list_files_in_directory(dir_path):
    """
    List all files in a directory
    
    Args:
        dir_path (str): Path to the directory
    
    Returns:
        list: List of file names
    """
    if os.path.exists(dir_path):
        return [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
    return []

def get_file_info(file_path):
    """
    Get information about a file
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        dict: File information
    """
    if not check_file_exists(file_path):
        return None
    
    stat = os.stat(file_path)
    return {
        'name': os.path.basename(file_path),
        'size': stat.st_size,
        'modified': stat.st_mtime,
        'path': file_path
    }