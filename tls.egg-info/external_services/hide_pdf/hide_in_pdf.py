from cryptography.fernet import Fernet
import base64
import secrets
import os
import datetime

def generate_key():
    """Generate a Fernet key with a specific prefix"""
    random_part = secrets.token_bytes(28)
    key = b"DZDZ" + random_part  # 32 bytes total as required by Fernet
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path, key):
    """Encrypt a file using Fernet"""
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
            return f.encrypt(file_data)
    except Exception as e:
        raise Exception(f"Encryption error: {e}")

def append_data_to_pdf(pdf_path, data, identifier):
    """Append binary data to PDF with clear markers"""
    try:
        # Read the existing PDF content
        with open(pdf_path, 'rb') as f:
            pdf_content = f.read()
        
        # Verify it's a valid PDF
        if not pdf_content.startswith(b'%PDF'):
            raise ValueError("Not a valid PDF file")
            
        # Create markers
        start_marker = f"\n%%{identifier}%%\n".encode()
        end_marker = f"\n%%END_{identifier}%%\n".encode()
        
        # Write everything back
        with open(pdf_path, 'wb') as f:
            f.write(pdf_content)  # Original PDF
            f.write(start_marker)
            f.write(base64.b64encode(data))  # Base64 encoded data
            f.write(end_marker)
            
        # Verify the file is still readable
        with open(pdf_path, 'rb') as f:
            test_read = f.read()
            if not test_read.startswith(b'%PDF'):
                raise ValueError("PDF corruption check failed")
                
    except Exception as e:
        raise Exception(f"PDF append error: {e}")

def hide_exes_in_pdf(pdf_path, server_exe, client_exe):
    """Hide executables in PDF with encryption for the client"""
    try:
        # Input validation
        for file_path in [pdf_path, server_exe, client_exe]:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
        # Read and append server executable (unencrypted)
        with open(server_exe, 'rb') as f:
            server_data = f.read()
        append_data_to_pdf(pdf_path, server_data, 'SERVER_EXE')
        print(f"Added server.exe ({len(server_data):,} bytes)")
        
        # Generate key and encrypt client
        key = generate_key()
        encrypted_client = encrypt_file(client_exe, key)
        
        # Add key and encrypted client
        append_data_to_pdf(pdf_path, key, 'KEY')
        append_data_to_pdf(pdf_path, encrypted_client, 'ENCRYPTED_CLIENT')
        print(f"Added encrypted client.exe ({len(encrypted_client):,} bytes)")
        
        return key.decode()
        
    except Exception as e:
        raise Exception(f"Hide operation failed: {e}")

def verify_embedded_data(pdf_path, original_server_size, original_client_size):
    """Verify the integrity of embedded data"""
    with open(pdf_path, 'rb') as f:
        content = f.read()
    
    # Extract server data
    server_start = content.find(b"\n%SERVER_EXE%\n")
    server_end = content.find(b"\n%END_SERVER_EXE%\n")
    if server_start == -1 or server_end == -1:
        raise ValueError("Server data not found")
    
    server_data = base64.b64decode(content[server_start:server_end])
    if len(server_data) != original_server_size:
        raise ValueError(f"Server size mismatch: {len(server_data)} vs {original_server_size}")

def calculate_checksums(pdf_path):
    """Calculate and store checksums for verification"""
    import hashlib
    with open(pdf_path, 'rb') as f:
        data = f.read()
    
    checksums = {
        'sha256': hashlib.sha256(data).hexdigest(),
        'md5': hashlib.md5(data).hexdigest()
    }
    
    # שמירת ה-checksums בקובץ נפרד
    with open(f"{pdf_path}.checksums", 'w') as f:
        for hash_type, value in checksums.items():
            f.write(f"{hash_type}: {value}\n")
            print(f"{hash_type}: {value}")

def add_metadata(pdf_path):
    """Add metadata about embedded files"""
    metadata = f"""
%%METADATA%%
Embedded files:
1. server.exe (unencrypted)
2. encryption key
3. client.exe (encrypted)
Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
%%END_METADATA%%
""".encode()
    
    with open(pdf_path, 'ab') as f:
        f.write(metadata)

def check_size_limits(pdf_path, server_size, client_size):
    """Verify total size won't exceed reasonable limits"""
    MAX_SIZE = 50 * 1024 * 1024  # 50MB
    estimated_size = os.path.getsize(pdf_path) + server_size + client_size
    
    if estimated_size > MAX_SIZE:
        raise ValueError(f"Total size ({estimated_size/1024/1024:.1f}MB) exceeds limit")

def log_operation(operation, details):
    """Log operations with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('embedding.log', 'a') as f:
        f.write(f"[{timestamp}] {operation}: {details}\n")
        
def main():
    pdf_path = "instructions.pdf"
    server_exe = "tls/server.exe"
    client_exe = "tls/client.exe"

    try:
        print("Starting file embedding process...")
        key = hide_exes_in_pdf(pdf_path, server_exe, client_exe)
        print("\nFiles embedded successfully!")
        print(f"Final PDF size: {os.path.getsize(pdf_path):,} bytes")
        print(f"\nEncryption key (save for verification): {key}")
        
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

if __name__ == "__main__":
    main()