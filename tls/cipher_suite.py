from dataclasses import dataclass
from enum import IntEnum
"""
{60,            // ID של ה-cipher suite
KEX_RSA,        // Key Exchange method
SIG_RSA,        // Signature algorithm
ENC_AES,        // Encryption algorithm
16,             // Block size
128,            // Key size
128,            // Export key size
DIG_SHA256,     // Digest algorithm
SSL_CIPHER_MODE_CBC}  // Cipher mode
"""
class KeyExchange(IntEnum):
    RSA = 1

class SignatureAlgorithm(IntEnum):
    RSA = 1

class EncryptionMethod(IntEnum):
    AES = 7  # צריך לוודא שזה המספר הנכון מהקוד של Wireshark

class DigestAlgorithm(IntEnum):
    SHA256 = 4  # צריך לוודא שזה המספר הנכון מהקוד של Wireshark

class CipherMode(IntEnum):
    CBC = 1

@dataclass
class CipherSuite:
    """TLS Cipher Suite compatible with Wireshark's definition"""
    id: int = 60  # TLS_RSA_WITH_AES_128_CBC_SHA256
    key_exchange: KeyExchange = KeyExchange.RSA
    signature: SignatureAlgorithm = SignatureAlgorithm.RSA
    encryption: EncryptionMethod = EncryptionMethod.AES
    block_size: int = 16
    key_size: int = 128
    export_key_size: int = 128
    digest: DigestAlgorithm = DigestAlgorithm.SHA256
    mode: CipherMode = CipherMode.CBC