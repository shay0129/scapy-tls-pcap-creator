from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto.cipher_block import Cipher_AES_128_CBC
from scapy.layers.tls.crypto.cipher_aead import Cipher_AES_256_GCM
from scapy.layers.inet import IP
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import struct

# Mapping of cipher suite values
CIPHER_SUITES = {
    0x3C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    # Add more cipher suites as needed
}

def P_hash(secret, seed, length, hash_name):
    result = b""
    A = seed
    backend = default_backend()
    while len(result) < length:
        h = hmac.HMAC(secret, hash_name(), backend=backend)
        h.update(A)
        A = h.finalize()
        h = hmac.HMAC(secret, hash_name(), backend=backend)
        h.update(A + seed)
        result += h.finalize()
    return result[:length]

def TLS_PRF(secret, label, seed, length, hash_name):
    return P_hash(secret, label + seed, length, hash_name)

def derive_keys(master_secret, client_random, server_random, cipher_suite):
    seed = client_random + server_random
    if 'SHA384' in cipher_suite:
        hash_name = hashes.SHA384
        key_length = 32  # AES-256
    else:
        hash_name = hashes.SHA256
        key_length = 16  # AES-128
    
    if 'GCM' in cipher_suite:
        iv_length = 4
        key_block = TLS_PRF(master_secret, b"key expansion", seed, 2 * (key_length + iv_length), hash_name)
        client_write_key = key_block[:key_length]
        server_write_key = key_block[key_length:2*key_length]
        client_write_IV = key_block[2*key_length:2*key_length+iv_length]
        server_write_IV = key_block[2*key_length+iv_length:]
    else:  # CBC
        mac_length = 32 if 'SHA256' in cipher_suite else 20  # SHA256 produces 32-byte MACs
        iv_length = 16
        key_block = TLS_PRF(master_secret, b"key expansion", seed, 2 * (mac_length + key_length + iv_length), hash_name)
        client_write_MAC_key = key_block[:mac_length]
        server_write_MAC_key = key_block[mac_length:2*mac_length]
        client_write_key = key_block[2*mac_length:2*mac_length+key_length]
        server_write_key = key_block[2*mac_length+key_length:2*mac_length+2*key_length]
        client_write_IV = key_block[2*mac_length+2*key_length:2*mac_length+2*key_length+iv_length]
        server_write_IV = key_block[2*mac_length+2*key_length+iv_length:]
        return client_write_MAC_key, server_write_MAC_key, client_write_key, server_write_key, client_write_IV, server_write_IV
    
    return client_write_key, server_write_key, client_write_IV, server_write_IV

def decrypt_tls_record_cbc(encrypted_record, key, iv, mac_key):
    cipher = Cipher_AES_128_CBC(key, iv)
    decrypted = cipher.decrypt(encrypted_record)
    padding_length = decrypted[-1]
    if padding_length > len(decrypted):
        raise ValueError("Invalid padding length")
    unpadded = decrypted[:-padding_length-1]
    mac = unpadded[-32:]  # Assuming SHA256 (32 bytes)
    plaintext = unpadded[:-32]
    # Here you should verify the MAC, but for simplicity, we'll skip it
    return plaintext

def decrypt_tls_record_gcm(encrypted_record, key, iv, seq_num):
    nonce = iv + struct.pack('!Q', seq_num)
    cipher = Cipher_AES_256_GCM(key)
    aad = struct.pack('!B', 23) + b'\x03\x03' + struct.pack('!H', len(encrypted_record) - 16)
    decrypted = cipher.decrypt(nonce, encrypted_record[:-16], aad, encrypted_record[-16:])
    return decrypted

def process_pcap(pcap_file, master_secret):
    packets = rdpcap(pcap_file)
    print(f"Loaded {len(packets)} packets from {pcap_file}")
    
    client_random = None
    server_random = None
    client_write_key = None
    server_write_key = None
    client_write_IV = None
    server_write_IV = None
    client_write_MAC_key = None
    server_write_MAC_key = None
    client_seq_num = 0
    server_seq_num = 0
    cipher_suite = None
    
    for i, packet in enumerate(packets):
        if TLS in packet:
            print(f"\nProcessing packet {i+1}: TLS packet found")
            if TLSClientHello in packet:
                print("TLS Client Hello found")
                client_random = packet[TLSClientHello].random_bytes
                print(f"Client Random: {client_random.hex()}")
            elif TLSServerHello in packet:
                print("TLS Server Hello found")
                server_random = packet[TLSServerHello].random_bytes
                print(f"Server Random: {server_random.hex()}")
                
                cipher_value = packet[TLSServerHello].cipher
                cipher_suite = CIPHER_SUITES.get(cipher_value, f"Unknown ({cipher_value})")
                print(f"Cipher Suite: {cipher_suite}")
            
            if client_random and server_random and cipher_suite and not client_write_key:
                print("Deriving keys...")
                keys = derive_keys(master_secret, client_random, server_random, cipher_suite)
                if 'GCM' in cipher_suite:
                    client_write_key, server_write_key, client_write_IV, server_write_IV = keys
                else:
                    client_write_MAC_key, server_write_MAC_key, client_write_key, server_write_key, client_write_IV, server_write_IV = keys
                print("Keys derived successfully")
                print(f"Client Write Key: {client_write_key.hex()}")
                print(f"Server Write Key: {server_write_key.hex()}")
                print(f"Client Write IV: {client_write_IV.hex()}")
                print(f"Server Write IV: {server_write_IV.hex()}")
            
            if TLSApplicationData in packet:
                print(f"TLS Application Data found in packet {i+1}")
                tls_data = packet[TLSApplicationData]
                encrypted_data = tls_data.data
                print(f"Encrypted data length: {len(encrypted_data)}")
                
                if IP in packet:
                    is_from_client = packet[IP].src < packet[IP].dst
                    key = client_write_key if is_from_client else server_write_key
                    iv = client_write_IV if is_from_client else server_write_IV
                    mac_key = client_write_MAC_key if is_from_client else server_write_MAC_key
                    seq_num = client_seq_num if is_from_client else server_seq_num
                else:
                    print("IP layer not found, skipping packet")
                    continue
                
                if not key or not iv:
                    print("Keys not yet derived, skipping decryption")
                    continue
                
                try:
                    if 'GCM' in cipher_suite:
                        decrypted_data = decrypt_tls_record_gcm(encrypted_data, key, iv, seq_num)
                    else:
                        # For CBC mode, the IV is the last 16 bytes of the previous ciphertext
                        if seq_num == 0:
                            actual_iv = iv
                        else:
                            actual_iv = encrypted_data[:16]
                            encrypted_data = encrypted_data[16:]
                        decrypted_data = decrypt_tls_record_cbc(encrypted_data, key, actual_iv, mac_key)
                    print(f"Decrypted data ({len(decrypted_data)} bytes):")
                    print(decrypted_data.hex())
                    
                    if is_from_client:
                        client_seq_num += 1
                    else:
                        server_seq_num += 1
                except Exception as e:
                    print(f"Failed to decrypt: {e}")
                    print(f"Key: {key.hex()}")
                    print(f"IV: {iv.hex()}")
                    print(f"Encrypted data: {encrypted_data.hex()}")

# Example usage
# cbc
pcap_file = "../api/output.pcap"
master_secret = bytes.fromhex("70f4ede7b1d0591f4ece40ec0bb70f0bc51eb5e772a379910df9141f3c565a42bf079eef62ebaa63d39b5a584e7cf782")



process_pcap(pcap_file, master_secret)