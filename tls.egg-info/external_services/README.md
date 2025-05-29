# File Embedding Service

A service for embedding executable files within PDF documents, designed as part of the CTF challenge infrastructure.

## Overview

This service implements secure file embedding mechanisms to:
1. Embed unencrypted server executable
2. Generate and embed encryption key
3. Encrypt and embed client executable
4. Provide integrity verification and logging

## Core Functionality

### File Embedding
```python
hide_exes_in_pdf(pdf_path, server_exe, client_exe)
```
- Embeds `server.exe` unencrypted
- Generates Fernet encryption key (with "DZDZ" prefix)
- Encrypts and embeds `client.exe`
- Uses clear markers for data sections

### Data Verification
```python
verify_embedded_data(pdf_path, original_server_size, original_client_size)
```
- Validates embedded data integrity
- Verifies file sizes match originals
- Checks PDF structure integrity

### Checksum Generation
```python
calculate_checksums(pdf_path)
```
- Generates SHA256 and MD5 checksums
- Stores checksums in companion file
- Enables verification of PDF integrity

### Metadata Management
```python
add_metadata(pdf_path)
```
- Records embedding timestamp
- Lists embedded components
- Provides file structure information

## Security Features

- Fernet symmetric encryption
- Base64 encoding for binary data
- PDF structure verification
- Size limit enforcement
- Integrity checksums

## Usage

```python
from external_services.embedding import hide_exes_in_pdf

def main():
    pdf_path = "instructions.pdf"
    server_exe = "tls/server.exe"
    client_exe = "tls/client.exe"

    try:
        key = hide_exes_in_pdf(pdf_path, server_exe, client_exe)
        print(f"Files embedded successfully. Key: {key}")
    except Exception as e:
        print(f"Embedding failed: {e}")
```

## File Structure
```
external_services/
├── README.md
├── embedding.py        # Core embedding functionality
├── verification.py     # Integrity verification
└── utils/
    ├── crypto.py      # Cryptographic operations
    ├── pdf.py         # PDF manipulation
    └── logging.py     # Operation logging
```

## Development Notes

- Maximum supported PDF size: 50MB
- Uses Fernet for client executable encryption
- Maintains original PDF readability
- Generates detailed operation logs

## Error Handling

The service implements comprehensive error checking:
- File existence validation
- Size limit verification
- PDF structure validation
- Embedding integrity checks

## Logging

Detailed logging of all operations including:
- File sizes and checksums
- Embedding timestamps
- Operation success/failure
- Error details

This service is part of the CTF project's infrastructure, providing secure file distribution mechanisms while maintaining challenge integrity.