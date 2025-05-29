# Scapy TLS 1.2 PCAP Creator

## Project Overview

This project provides a robust framework for simulating TLS 1.2 handshake sessions and generating corresponding PCAP files using Scapy. It allows for detailed configuration of client and server behaviors, including client certificate usage, to create realistic network traffic captures for analysis and testing purposes. The core functionality revolves around the `UnifiedTLSSession` class, which orchestrates the TLS handshake and data exchange.

This tool was originally developed as part of a larger CTF (Capture The Flag) challenge focused on network security and the TLS protocol.

## Table of Contents
- [Core Features](#core-features)
- [TLS Handshake Implementation Details](#tls-handshake-implementation-details)
  - [Client Hello](#client-hello)
  - [Server Hello](#server-hello)
  - [Client Key Exchange](#client-key-exchange)
  - [Master Secret Generation](#master-secret-generation)
  - [Change Cipher Spec (Client & Server)](#change-cipher-spec-client--server)
  - [SSLKeyLog File Creation](#sslkeylog-file-creation)
  - [Application Data Encryption](#application-data-encryption)
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

### Server Hello
The server responds with its own random bytes, the selected cipher suite (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA256`), and relevant extensions.

### Client Key Exchange
The client generates a Pre-Master Secret, encrypts it using the server's public key (obtained from the server's certificate, assuming RSA Key Exchange), and sends it to the server. This implementation supports optional sending of a client certificate. The Pre-Master Secret is encrypted using PKCS#1 v1.5 padding.

*Notice: In TLS 1.2 with RSA Key Exchange, no `ServerKeyExchange` message is typically sent as the server's public key is sufficient.*

### Master Secret Generation
Both client and server derive the same Master Secret using the Pre-Master Secret and the random values exchanged. The server decrypts the Pre-Master Secret using its private key. The Master Secret is computed using a PRF (Pseudo-Random Function).

### Change Cipher Spec (Client & Server)
Both client and server send `ChangeCipherSpec` messages to notify the other party that subsequent messages will be encrypted using the negotiated settings. This is followed by an encrypted `Finished` message to verify the handshake integrity.

### SSLKeyLog File Creation
To enable debugging and analysis, the `CLIENT_RANDOM` and `master_secret` are exported to an SSLKeyLog file. This file can be loaded into Wireshark to decrypt the captured TLS traffic. The format is: `CLIENT_RANDOM <client_random_hex> <master_secret_hex>`.

### Application Data Encryption
The tool supports sending and receiving encrypted application data over the established TLS session, using AES-128-CBC with HMAC-SHA256 (based on the example cipher suite).

---
## Technical Skills Demonstrated

This project showcases proficiency in:
* **Network Protocols**: Deep understanding and implementation of TLS 1.2.
* **Python Libraries**: Extensive use of Scapy for packet manipulation and `cryptography` for cryptographic operations.
* **Cryptography**: Implementation of key exchange, pre-master and master secret generation, and application data encryption.
* **PCAP File Analysis**: Generation of PCAP files suitable for analysis with tools like Wireshark and Tshark.

---
## Prerequisites

* Python (version used during development, e.g., 3.8+)
* Scapy
* Cryptography library
* (List any other specific Python libraries from your `requirements.txt` or `setup.py` that are essential for this part)

---
## Installation

1.  Clone the repository:
    ```bash
    git clone [https://github.com/shay0129/scapy-tls-pcap-creator.git](https://github.com/shay0129/scapy-tls-pcap-creator.git)
    cd scapy-tls-pcap-creator
    ```
2.  Install dependencies (ensure you have a `requirements.txt` for this part or adapt the `pip install -e .` if you have a `setup.py` for this specific project):
    ```bash
    pip install -r requirements.txt 
    # Or if using setup.py from the original project, ensure it's adapted:
    # pip install -e . 
    ```
    *(Based on your original README, you used `pip install -e .`. If this sub-project has its own `setup.py` or a relevant `requirements.txt`, specify that. Otherwise, list individual pip installs for Scapy, cryptography, etc.)*

---
## Usage

The main script to run the TLS session simulation and generate the PCAP is typically `tls/main.py` (based on your original `python -m tls.main`).

```bash
python -m tls.main 
# Or if main.py is in the root after filtering and path renaming:
# python main.py
