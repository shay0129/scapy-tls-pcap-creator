# Scapy TLS 1.2 PCAP Creator

## Project Overview

This project provides a robust framework for simulating TLS 1.2 handshake sessions and generating corresponding PCAP files using Scapy. It allows for detailed configuration of client and server behaviors, including client certificate usage, to create realistic network traffic captures for analysis and testing purposes. The core functionality revolves around the `UnifiedTLSSession` class, which orchestrates the TLS handshake and data exchange.

**Project Statistics:**
- **Total Lines of Code:** 4,030+ lines across 22 Python modules
- **Core TLS Implementation:** 976 lines (session.py + handshake modules)
- **Cryptographic Operations:** 612 lines (crypto utilities + key management)
- **Certificate Management:** 536 lines (certificate chain validation + verification)
- **Packet Processing & Validation:** 509 lines (packet storage + validation)
- **Configuration & Error Handling:** 397 lines (robust system management)

This tool was originally developed as part of a larger CTF (Capture The Flag) challenge focused on network security and the TLS protocol, demonstrating advanced cryptographic implementation skills.

## Table of Contents
- [Core Features](#core-features)
- [TLS Handshake Implementation Details](#tls-handshake-implementation-details)
  - [Client Hello](#client-hello)
  - [Server Hello](#server-hello)
  - [Certificate Exchange](#certificate-exchange)
  - [Client Key Exchange](#client-key-exchange)
  - [Master Secret Generation](#master-secret-generation)
  - [Key Block Generation and Encryption](#key-block-generation-and-encryption)
  - [Change Cipher Spec (Client & Server)](#change-cipher-spec-client--server)
  - [Application Data Encryption](#application-data-encryption)
  - [SSLKeyLog File Creation](#sslkeylog-file-creation)
- [Technical Skills Demonstrated](#technical-skills-demonstrated)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---
## Core Features

1.  **TLS 1.2 Handshake Simulation**: Accurately simulates the TLS 1.2 handshake process, including certificate exchange (optional client certificate) and negotiation of encryption parameters.
2.  **PCAP File Generation**: Creates PCAP files of the simulated TLS sessions, allowing for offline analysis with tools like Wireshark.
3.  **SSLKeyLog File Export**: Generates an SSLKeyLog file containing `CLIENT_RANDOM` and `master_secret` values, enabling decryption of the captured TLS traffic in Wireshark.
4.  **Customizable Sessions**: Supports configuration for multiple client sessions with different parameters (e.g., with or without client certificates, different client IPs/ports).
5.  **Application Data Exchange**: Facilitates exchange of encrypted application data (e.g., HTTP GET requests and responses) over the established TLS session.

---
## TLS Handshake Implementation Details

This project implements the key stages of a TLS 1.2 handshake using Scapy. The process ensures the secure generation of session keys for encryption and integrity checks.

### Client Hello

The client initiates the handshake by sending supported ciphers, extensions (like SNI, supported groups, signature algorithms), and random bytes. The client random is a combination of GMT Unix timestamp and 28 random bytes.

**Implementation (298 lines in `client.py`):**
```python
def create_client_hello(
    session: object,
    extensions: Optional[ClientExtensions] = None
    ) -> TLSClientHello:
    """
    Create a Client Hello message for TLS handshake.
    """
    # Ensure SNI is set and valid before handshake
    if not getattr(session, 'sni', None) or not str(session.sni).strip():
        session.sni = 'Pasdaran.local'
        logging.warning("Session SNI was not set or empty. Defaulting to 'Pasdaran.local'")

    # Generate client random as one piece
    session.client_random = os.urandom(32)  # Generate all 32 bytes at once
    logging.info(f"Generated client_random: {session.client_random.hex()}")

    # Extract GMT time and random bytes for TLSClientHello
    gmt_time = int.from_bytes(session.client_random[:4], 'big')
    random_bytes = session.client_random[4:]

    if not extensions:
        extensions = ClientExtensions(
            server_name=session.sni,
            supported_groups=["x25519"],
            signature_algorithms=["sha256+rsa"]
        )

    return TLSClientHello(
        version=TLSVersion.TLS_1_2,
        ciphers=[TLS_RSA_WITH_AES_128_CBC_SHA256],
        ext=extensions.get_extension_list(),
        gmt_unix_time=gmt_time,
        random_bytes=random_bytes
    )
```

**Key Features:**
- **SNI Extension**: Enables virtual hosting by specifying server name
- **Signature Algorithms**: Advertises supported signature/hash combinations
- **Supported Groups**: Cryptographic curve support for key exchange
- **Secure Random Generation**: Uses `os.urandom()` for cryptographic security

### Server Hello

The server responds with its own random bytes, the selected cipher suite (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA256`), and relevant extensions.

**Implementation (260 lines in `server.py`):**
```python
def create_server_hello(
        session: SessionState,
        extensions: Optional[ServerExtensions] = None
        ) -> TLSServerHello:
    """
    Create Server Hello message.
    
    Args:
        session: TLS session instance
        extensions: Optional server extensions configuration
        
    Returns:
        TLSServerHello: Configured hello message
    """
    # Generate server random as one piece
    session.server_random = os.urandom(32)
    logging.info(f"Generated server_random: {session.server_random.hex()}")
    
    # Extract GMT time and random bytes for TLSServerHello
    gmt_time = int.from_bytes(session.server_random[:4], 'big')
    random_bytes = session.server_random[4:]

    # Configure server extensions (subset of client extensions)
    server_extensions = []
    if extensions:
        server_extensions = extensions.get_extension_list()

    return TLSServerHello(
        version=TLSVersion.TLS_1_2,
        cipher=TLS_RSA_WITH_AES_128_CBC_SHA256,
        ext=server_extensions,
        gmt_unix_time=gmt_time,
        random_bytes=random_bytes
    )
```

**Important Notes:**
- Server MUST NOT echo back SNI extension (RFC 6066 compliance)
- Only includes extensions the server supports and wishes to acknowledge
- Random generation is cryptographically secure using `os.urandom()`

### Certificate Exchange

The server sends its certificate chain, and optionally the client sends its certificate if mutual authentication is required.

**Server Certificate Implementation (183 lines in `verify.py`):**
```python
def prepare_certificate_chain(session: SessionState) -> TLSCertificate:
    """
    Prepare server certificate chain for transmission.
    
    Args:
        session: Current TLS session state
        
    Returns:
        TLSCertificate: Certificate message with complete chain
        
    Raises:
        CertificateError: If certificate loading or validation fails
    """
    try:
        # Load server certificate from PEM file
        with open(session.config.certificates.server_cert, 'rb') as f:
            server_cert_data = f.read()
        
        # Load CA certificate for chain completion
        with open(session.config.certificates.ca_cert, 'rb') as f:
            ca_cert_data = f.read()
        
        # Parse certificates using cryptography library
        server_cert = x509.load_pem_x509_certificate(server_cert_data)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
        
        # Create certificate chain (server cert + intermediate + root)
        cert_chain = [
            server_cert.public_bytes(serialization.Encoding.DER),
            ca_cert.public_bytes(serialization.Encoding.DER)
        ]
        
        return TLSCertificate(certs=cert_chain)
        
    except FileNotFoundError as e:
        raise CertificateError(f"Certificate file not found: {e}")
    except Exception as e:
        raise CertificateError(f"Certificate processing failed: {e}")
```

### Client Key Exchange

The client generates a Pre-Master Secret, encrypts it using the server's public key (obtained from the server's certificate, assuming RSA Key Exchange), and sends it to the server.

**Implementation (from `crypto.py`):**
```python
def generate_pre_master_secret() -> bytes:
    """
    Generate TLS 1.2 pre-master secret.
    
    Returns:
        bytes: 48-byte pre-master secret with TLS version
    """
    try:
        # Convert TLS version to bytes first
        tls_version_bytes = TLSVersion.TLS_1_2.to_bytes(2, byteorder='big')
        
        # Generate 46 random bytes
        random_bytes = secrets.token_bytes(46)
        
        # Combine TLS version bytes with random bytes
        pre_master_secret = tls_version_bytes + random_bytes
        
        return pre_master_secret
    
    except Exception as e:
        raise CryptoError(f"Failed to generate pre-master secret: {e}")

def encrypt_pre_master_secret(
    pre_master_secret: bytes,
    server_public_key: rsa.RSAPublicKey
) -> bytes:
    """
    Encrypt pre-master secret using server's public key.
    
    Args:
        pre_master_secret: Pre-master secret to encrypt
        server_public_key: Server's RSA public key
        
    Returns:
        bytes: Encrypted pre-master secret
    """
    try:
        if len(pre_master_secret) != 48:
            raise ValidationError("Pre-master secret must be 48 bytes")
            
        return server_public_key.encrypt(
            pre_master_secret,
            asymmetric_padding.PKCS1v15()
        )
        
    except Exception as e:
        raise CryptoError(f"Failed to encrypt pre-master secret: {e}")
```

**Security Notes:**
- Pre-Master Secret uses TLS version (0x0303) + 46 random bytes
- RSA encryption uses PKCS#1 v1.5 padding (TLS 1.2 standard)
- All cryptographic operations use secure random number generation

### Master Secret Generation

Both client and server derive the same Master Secret using the Pre-Master Secret and the random values exchanged.

**Implementation (266 lines in `crypto.py`):**
```python
def P_hash(secret: bytes, seed: bytes, length: int) -> bytes:
    """
    TLS 1.2 P_hash function for PRF.
    
    Args:
        secret: Secret key
        seed: Seed value
        length: Desired output length
        
    Returns:
        bytes: Pseudo-random output of specified length
    """
    try:
        result = bytearray()
        a_value = seed
        while len(result) < length:
            a_value = hmac.new(secret, a_value, hashlib.sha256).digest()
            result.extend(hmac.new(secret, a_value + seed, hashlib.sha256).digest())
        return bytes(result[:length])
    except Exception as e:
        raise CryptoError(f"P_hash computation failed: {e}")

def generate_master_secret(
    pre_master_secret: bytes, 
    client_random: bytes, 
    server_random: bytes
) -> bytes:
    """
    Generate Master Secret using TLS PRF (Pseudo-Random Function).
    
    Args:
        pre_master_secret: 48-byte secret from key exchange
        client_random: 32-byte random from ClientHello
        server_random: 32-byte random from ServerHello
        
    Returns:
        bytes: 48-byte master secret
    """
    # TLS 1.2 PRF uses HMAC-SHA256 for key expansion
    seed = b"master secret" + client_random + server_random
    
    # Generate 48-byte master secret using PRF
    master_secret = P_hash(pre_master_secret, seed, 48)
    
    logging.info(f"Generated master_secret: {master_secret.hex()}")
    return master_secret
```

### Key Block Generation and Encryption

After master secret generation, both parties derive encryption keys, MAC keys, and IVs from the master secret.

**Implementation (346 lines in `keys.py`):**
```python
@dataclass
class KeyBlock:
    """TLS 1.2 key block containing all derived keys"""
    client_write_mac_key: bytes
    server_write_mac_key: bytes
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes

def generate_key_block(master_secret: bytes, client_random: bytes, server_random: bytes) -> KeyBlock:
    """
    Generate key block from master secret for AES-128-CBC-SHA256.
    
    Key sizes for TLS_RSA_WITH_AES_128_CBC_SHA256:
    - MAC key: 32 bytes (SHA256)
    - Encryption key: 16 bytes (AES-128)
    - IV: 16 bytes (AES block size)
    """
    # Key expansion seed: "key expansion" + server_random + client_random
    seed = b"key expansion" + server_random + client_random
    
    # Total key material needed: (32 + 16 + 16) * 2 = 128 bytes
    key_material_length = (32 + 16 + 16) * 2
    key_material = P_hash(master_secret, seed, key_material_length)
    
    # Extract keys in order specified by RFC 5246
    offset = 0
    client_write_mac_key = key_material[offset:offset+32]; offset += 32
    server_write_mac_key = key_material[offset:offset+32]; offset += 32
    client_write_key = key_material[offset:offset+16]; offset += 16
    server_write_key = key_material[offset:offset+16]; offset += 16
    client_write_iv = key_material[offset:offset+16]; offset += 16
    server_write_iv = key_material[offset:offset+16]; offset += 16
    
    return KeyBlock(
        client_write_mac_key=client_write_mac_key,
        server_write_mac_key=server_write_mac_key,
        client_write_key=client_write_key,
        server_write_key=server_write_key,
        client_write_iv=client_write_iv,
        server_write_iv=server_write_iv
    )
```

### Change Cipher Spec (Client & Server)

Both client and server send `ChangeCipherSpec` messages to notify the other party that subsequent messages will be encrypted using the negotiated settings. This is followed by an encrypted `Finished` message to verify the handshake integrity.

### Application Data Encryption

The tool supports sending and receiving encrypted application data over the established TLS session, using AES-128-CBC with HMAC-SHA256.

**Implementation:**
```python
def encrypt_application_data(
    plaintext: bytes, 
    seq_num: int, 
    key_block: KeyBlock, 
    is_client: bool
) -> bytes:
    """
    Encrypt application data using AES-128-CBC with HMAC-SHA256.
    
    Args:
        plaintext: Application data to encrypt
        seq_num: TLS record sequence number
        key_block: Derived encryption keys
        is_client: True if encrypting client data, False for server
        
    Returns:
        bytes: Encrypted TLS record data
    """
    # Select appropriate keys based on sender
    if is_client:
        mac_key = key_block.client_write_mac_key
        enc_key = key_block.client_write_key
        iv = key_block.client_write_iv
    else:
        mac_key = key_block.server_write_mac_key
        enc_key = key_block.server_write_key
        iv = key_block.server_write_iv
    
    # Compute HMAC over seq_num + type + version + length + plaintext
    mac_data = (
        seq_num.to_bytes(8, 'big') +
        b'\x17' +  # Application Data type
        TLSVersion.TLS_1_2.value.to_bytes(2, 'big') +
        len(plaintext).to_bytes(2, 'big') +
        plaintext
    )
    mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
    
    # Create plaintext with MAC and padding for CBC
    plaintext_with_mac = plaintext + mac
    
    # PKCS#7 padding for AES-CBC
    pad_length = 16 - (len(plaintext_with_mac) % 16)
    padding = bytes([pad_length - 1] * pad_length)
    padded_plaintext = plaintext_with_mac + padding
    
    # Encrypt using AES-128-CBC
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext
```

### SSLKeyLog File Creation

To enable debugging and analysis, the `CLIENT_RANDOM` and `master_secret` are exported to an SSLKeyLog file compatible with Wireshark.

**Implementation:**
```python
def write_ssl_keylog(session: SessionState, output_dir: Path) -> None:
    """
    Write SSL key log file for Wireshark decryption.
    
    Format: CLIENT_RANDOM <client_random_hex> <master_secret_hex>
    
    Args:
        session: TLS session containing secrets
        output_dir: Directory to write keylog file
    """
    keylog_path = output_dir / "ssl_key_log.log"
    
    try:
        with open(keylog_path, 'a', encoding='utf-8') as f:
            # Write CLIENT_RANDOM entry for Wireshark
            keylog_entry = (
                f"CLIENT_RANDOM "
                f"{session.client_random.hex().upper()} "
                f"{session.master_secret.hex().upper()}\n"
            )
            f.write(keylog_entry)
            
        logging.info(f"SSL keylog written to: {keylog_path}")
        
    except IOError as e:
        logging.error(f"Failed to write SSL keylog: {e}")
```

**Wireshark Configuration:**
To decrypt the captured TLS traffic:
1. In Wireshark, go to Edit → Preferences → Protocols → TLS
2. Set "Pre-Master-Secret log filename" to your `ssl_key_log.log` file
3. Reload the PCAP file to see decrypted application data

---
## Technical Skills Demonstrated

This project and implementation showcases advanced proficiency in:

### **🔐 Cryptographic Implementation**
* **TLS Protocol Expertise**: Complete implementation of TLS 1.2 handshake, including all message types and cryptographic operations
* **Key Management**: RSA key exchange, pre-master secret generation, master secret derivation using PRF
* **Symmetric Cryptography**: AES-128-CBC encryption with HMAC-SHA256 authentication for application data
* **Certificate Handling**: X.509 certificate parsing, validation, and chain verification

### **🌐 Network Security & Analysis**
* **Protocol Engineering**: Custom TLS session simulation with configurable client/server behaviors
* **Traffic Generation**: Realistic network packet creation for forensics training and security research
* **PCAP Analysis**: Generated traffic suitable for Wireshark analysis with SSL keylog integration
* **Network Forensics**: Packet validation and structured data extraction

### **💻 Advanced Python Development**
* **Scapy Mastery**: Advanced packet crafting, TLS layer manipulation, and custom protocol extensions
* **Cryptography Libraries**: Integration of `cryptography`, `pyOpenSSL`, and `pycryptodome` for robust crypto operations
* **Architecture Design**: Modular codebase with separation of concerns (handshake, crypto, validation, storage)
* **Error Handling**: Comprehensive exception handling and logging for production-ready code

### **🏗️ Software Engineering Practices**
* **Professional Packaging**: Modern Python packaging with `setup.py`, proper dependency management
* **Documentation**: Comprehensive technical documentation and code comments
* **Testing & Validation**: Packet validation, cryptographic verification, and edge case handling
* **Code Organization**: Clean module structure with 4,030+ lines across 22 specialized modules

---
## Prerequisites & Installation

### **System Requirements**
* **Python 3.8 or higher** (required for modern cryptography libraries)
* **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+), or macOS 10.14+
* **Memory**: Minimum 4GB RAM (8GB recommended for large PCAP analysis)
* **Disk Space**: 500MB for installation + additional space for generated PCAP files

### **Required Python Libraries**
Install dependencies using the provided `requirements.txt`:
```bash
pip install -r requirements.txt
```

**Core Dependencies:**
* `scapy==2.6.1` - Advanced packet manipulation and analysis
* `cryptography==44.0.0` - Modern cryptographic operations
* `pycryptodome==3.21.0` - Additional crypto primitives
* `pyOpenSSL==24.3.0` - SSL/TLS certificate handling

### **Recommended Tools for Analysis**
* **Wireshark** (latest version) - Essential for PCAP analysis and TLS decryption
* **Hex Editor** (HxD, GHex, or hexedit) - For binary data analysis
* **OpenSSL CLI** - Certificate inspection and cryptographic operations
* **Text Editor** with syntax highlighting - For code analysis

### **Installation Methods**

#### **Method 1: Quick Setup (Recommended)**
```bash
# Clone the repository
git clone https://github.com/shay0129/scapy-tls-pcap-creator.git
cd scapy-tls-pcap-creator

# Install dependencies
pip install -r requirements.txt

# Run the tool
python -m tls.main
```

#### **Method 2: Development Setup**
```bash
# Install in editable mode for development
pip install -e .

# Use the command-line tool
tls-pcap-creator
```

---
## Certificate and Key Management

All certificate and key file paths are managed via the `CertificatePaths` class in the codebase. By default, certificates and keys are expected in `tls/certificates/certs/`:

- `ca.crt`, `ca.key` (CA certificate and key)
- `server.crt`, `server.key` (Server certificate and key)
- `client.crt`, `client.key` (Client certificate and key)

If any certificate or key is missing or invalid, the simulation will log a clear error and exit. Ensure all files are present and valid before running the simulation.

---
## SNI and Extension Support

- **SNI (Server Name Indication)** is always set and included in both client and server hello messages.
- The handshake supports and correctly handles TLS extensions, including SNI and others (e.g., supported groups, signature algorithms).

---
## Error Handling and Logging

- The simulation includes robust error handling for missing/invalid certificates, keys, and handshake failures.
- All errors and handshake steps are logged to files in `tls/logs/`.
- Fast failure is implemented: the simulation will exit early if a critical error is detected.

---
## Installation

### **Quick Start**
1. Clone the repository:
   ```bash
   git clone https://github.com/shay0129/scapy-tls-pcap-creator.git
   cd scapy-tls-pcap-creator
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### **Development Installation**
For development work:
```bash
pip install -e .
```

This installs the package in editable mode and provides the `tls-pcap-creator` command-line tool.

---
## Usage

### **Running the TLS Session Simulation**

Run the main script to generate PCAP files with TLS sessions:

```bash
python -m tls.main
```

Or if installed as a package:
```bash
tls-pcap-creator
```

This will:
* Create two simulated TLS 1.2 sessions:
  * One with a client certificate (Client 1)
  * One without a client certificate (Client 2)
* Generate a PCAP file (default location: `tls/output/capture.pcap`)
* Create detailed log files in the `tls/logs/` directory
* Generate an SSL keylog file for decrypting the TLS traffic

### **Output Files**

* **PCAP file**: Contains the captured network packets (`tls/output/capture.pcap`)
* **Log files**: Detailed logs of the TLS handshake process (`tls/logs/tls_session.log`)
* **SSL keylog file**: Contains the necessary secrets for decrypting TLS traffic (`tls/logs/ssl_key_log.log`)

### **Configuration Options**

The tool supports various configuration options through the `config.py` module:
- Custom certificate paths
- Different client/server IP addresses and ports
- Session parameters and extensions
- Logging levels and output directories

### **Example Session Output**
```
[INFO] Starting TLS 1.2 session simulation...
[INFO] Generated client_random: a1b2c3d4e5f6...
[INFO] Generated server_random: f6e5d4c3b2a1...
[INFO] Generated pre_master_secret: 0303a1b2c3d4...
[INFO] Generated master_secret: deadbeefcafe...
[INFO] SSL keylog written to: tls/logs/ssl_key_log.log
[INFO] PCAP saved to: tls/output/capture.pcap
```

---
## Project Architecture

### **Module Structure**
```
tls/
├── handshake/          # TLS handshake implementation (558 lines)
│   ├── client.py       # Client-side handshake logic (298 lines)
│   └── server.py       # Server-side handshake logic (260 lines)
├── crypto/             # Cryptographic operations (346 lines)
│   └── keys.py         # Key generation and management
├── certificates/       # Certificate handling (311 lines)
│   ├── chain.py        # Certificate chain validation (128 lines)
│   └── verify.py       # Certificate verification (183 lines)
├── utils/              # Utility functions (886 lines)
│   ├── crypto.py       # Cryptographic utilities (266 lines)
│   ├── cert.py         # Certificate utilities (225 lines)
│   ├── packet.py       # Packet manipulation (230 lines)
│   └── logging.py      # Logging configuration (165 lines)
├── session.py          # Main session orchestration (418 lines)
├── session_state.py    # Session state management (321 lines)
├── packet_storage.py   # PCAP storage logic (105 lines)
├── packet_validator.py # Packet validation (174 lines)
└── main.py            # Entry point (151 lines)
```

### **Key Design Patterns**
- **State Management**: Centralized session state with `SessionState` class
- **Factory Pattern**: Handshake message creation with dedicated factory functions
- **Strategy Pattern**: Configurable extensions and cipher suites
- **Observer Pattern**: Comprehensive logging and monitoring throughout the flow

---
## Known Limitations

While this TLS PCAP creator provides comprehensive functionality for educational and testing purposes, there are some current limitations:

* **TLS Version Support**: The tool currently focuses on TLS 1.2 and does not support TLS 1.3 or earlier versions.
* **Key Exchange Methods**: Only RSA key exchange is implemented; other methods (e.g., ECDHE, DHE) are not currently supported.
* **Advanced TLS Features**: Limited support for advanced TLS features such as:
  - OCSP stapling
  - Session resumption and session tickets
  - TLS renegotiation
  - Perfect Forward Secrecy (PFS) key exchanges
* **Cipher Suite Coverage**: While multiple cipher suites are supported, the implementation focuses on commonly used algorithms (AES, 3DES, RC4).
* **Real Network Integration**: This is a simulation tool and does not handle real network conditions like packet loss, retransmissions, or network delays.

These limitations are intentional design choices to maintain focus on the core TLS 1.2 implementation and educational value of the project.

---
## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Make your changes and commit them
4. Push to your forked repository
5. Submit a pull request describing your changes

Please ensure your code adheres to the existing style and includes appropriate tests.

---
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
## Acknowledgments

* Inspired by real-world network security challenges and the need for effective TLS traffic analysis tools.
* Utilizes Scapy, a powerful Python library for network packet manipulation and analysis.
* Leverages the `cryptography` library for robust and secure cryptographic operations.

---
## Troubleshooting

If you encounter errors during simulation:

* **Certificate or Key Not Found**: Ensure all required certificate and key files exist in `tls/certificates/certs/`.
* **Permission Errors**: Run the tool with appropriate permissions to access files and directories.
* **Import/Attribute Errors**: Make sure you are using the latest code, and that all dependencies are installed.
* **Detailed Logs**: Check the log files in `tls/logs/` for detailed error messages and troubleshooting hints.
* **Missing or invalid certificates/keys**: Ensure all required files are present in `tls/certificates/certs/` and are valid PEM files.
* **PCAP not generated**: Check for errors in `tls/logs/tls_session.log` and ensure you have write permissions to the output directory.
* **Wireshark decryption not working**: Make sure you are using the correct SSL keylog file and that the PCAP contains the expected TLS handshake.
* **Python version errors**: Use Python 3.8 or higher.
* **Other issues**: Review log files in `tls/logs/` for detailed error messages.

