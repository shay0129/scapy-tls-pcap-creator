from dataclasses import dataclass
from enum import Enum

class CipherMode(Enum):
    CBC = "CBC"
    GCM = "GCM"

class CipherType(Enum):
    AES_128 = "AES-128"
    AES_256 = "AES-256"

@dataclass
class CipherSuite:
    """TLS Cipher Suite Configuration"""
    cipher_type: CipherType
    cipher_mode: CipherMode
    hash_algo: str
    compression: int = 0  # 0 means no compression

    @property
    def name(self) -> str:
        return f"TLS_{self.cipher_type.value}_{self.cipher_mode.value}_{self.hash_algo}"

    @property
    def key_size(self) -> int:
        return 16 if self.cipher_type == CipherType.AES_128 else 32