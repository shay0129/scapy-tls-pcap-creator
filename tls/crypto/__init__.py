"""
TLS cryptographic operations package.
Provides encryption and key handling functionality.
"""

from .keys import encrypt_and_send_application_data, handle_ssl_key_log

__all__ = [
    'encrypt_and_send_application_data',
    'handle_ssl_key_log'
]