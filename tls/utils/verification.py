"""
Verification utilities module.
Provides functions for verifying master secrets, key pairs and other cryptographic materials.
"""

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey

from dataclasses import dataclass, field
from pathlib import Path
import hmac
from typing import Union, Optional, List
import logging
from time import time
from tls.constants import CryptoConstants
from tls.utils.crypto import compare_to_original

class VerificationError(Exception):
    """Base exception for verification operations"""
    pass

class MasterSecretError(VerificationError):
    """Raised when master secret verification fails"""
    pass

class KeyPairError(VerificationError):
    """Raised when key pair verification fails"""
    pass

class PreMasterSecretError(VerificationError):
    """Raised when pre-master secret verification fails"""
    pass

@dataclass
class LogEntry:
    """Represents a parsed log entry"""
    client_random: bytes
    master_secret: bytes
    timestamp: float = field(default_factory=time)

    @classmethod
    def from_line(cls, line: str) -> Optional['LogEntry']:
        """Parse a log line into a LogEntry"""
        try:
            parts = line.strip().split()
            if len(parts) != 3 or parts[0] != "CLIENT_RANDOM":
                logging.warning(f"Invalid log format: {line.strip()}")
                return None
                
            return cls(
                client_random=bytes.fromhex(parts[1]),
                master_secret=bytes.fromhex(parts[2])
            )
        except (ValueError, IndexError) as e:
            logging.warning(f"Failed to parse log line: {e}")
            return None

class SecurityVerifier:
    """Handles various security verification operations"""

    @staticmethod
    def verify_key_sizes(
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey,
        expected_size: int = CryptoConstants.RSA_KEY_SIZE
    ) -> None:
        """Verify key sizes match expected size"""
        if private_key.key_size != expected_size:
            raise KeyPairError(
                f"Private key must be {expected_size} bits, got {private_key.key_size}"
            )
        if public_key.key_size != expected_size:
            raise KeyPairError(
                f"Public key must be {expected_size} bits, got {public_key.key_size}"
            )

    @staticmethod
    def verify_key_numbers(
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey
    ) -> None:
        """Verify public key numbers match"""
        try:
            priv_numbers = private_key.public_key().public_numbers()
            pub_numbers = public_key.public_numbers()
            
            for name, (pub, priv) in {
                'modulus': (pub_numbers.n, priv_numbers.n),
                'exponent': (pub_numbers.e, priv_numbers.e)
            }.items():
                if not compare_to_original(str(pub).encode(), str(priv).encode()):
                    raise KeyPairError(f"Public key {name} does not match private key")
                    
        except Exception as e:
            raise KeyPairError(f"Failed to verify key numbers: {e}")

    @staticmethod
    def verify_signature(
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey
    ) -> None:
        """Verify signature operation with key pair"""
        try:
            message = b"Test message for key verification"
            
            padding = asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            )
            
            signature = private_key.sign(
                message,
                padding,
                hashes.SHA256()
            )
            
            try:
                public_key.verify(
                    signature,
                    message,
                    padding,
                    hashes.SHA256()
                )
            except InvalidKey:
                raise KeyPairError("Signature verification failed")
                
        except Exception as e:
            raise KeyPairError(f"Failed to verify signature operation: {e}")

    @staticmethod
    def verify_pre_master_secret(
        decrypted: bytes,
        original: bytes
    ) -> bool:
        """Verify decrypted pre-master secret matches original"""
        try:
            if not decrypted or not original:
                return False
                
            if len(decrypted) != CryptoConstants.PRE_MASTER_SECRET_SIZE:
                raise PreMasterSecretError("Invalid pre-master secret length")
                
            return hmac.compare_digest(decrypted, original)
            
        except Exception as e:
            logging.error(f"Pre-master secret verification failed: {e}")
            return False

def read_log_entries(log_file: Union[str, Path]) -> List[LogEntry]:
    """Read and parse log entries from file"""
    try:
        log_path = Path(log_file)
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")
            
        entries = []
        with log_path.open("r") as f:
            for line_num, line in enumerate(f, 1):
                entry = LogEntry.from_line(line)
                if entry:
                    entries.append(entry)
                
        if not entries:
            raise MasterSecretError("No valid entries found in log file")
            
        return entries
        
    except Exception as e:
        raise MasterSecretError(f"Failed to read log entries: {e}")

def verify_master_secret(
    client_random: bytes,
    master_secret: bytes,
    log_file: Union[str, Path]
) -> bool:
    """Verify the master secret against the log file"""
    try:
        entries = read_log_entries(log_file)
        
        for entry in entries:
            if (compare_to_original(entry.client_random, client_random) and
                compare_to_original(entry.master_secret, master_secret)):
                logging.info("Found matching master secret")
                return True
                
        logging.warning("No matching CLIENT_RANDOM found")
        return False
        
    except Exception as e:
        raise MasterSecretError(f"Master secret verification failed: {e}")

def verify_key_pair(
    private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    key_size: int = CryptoConstants.RSA_KEY_SIZE
) -> bool:
    """Verify that a public key matches a private key"""
    try:
        verifier = SecurityVerifier()
        verifier.verify_key_sizes(private_key, public_key, key_size)
        verifier.verify_key_numbers(private_key, public_key)
        verifier.verify_signature(private_key, public_key)
        
        logging.info("Key pair verification successful")
        return True
        
    except Exception as e:
        raise KeyPairError(f"Key pair verification failed: {e}")