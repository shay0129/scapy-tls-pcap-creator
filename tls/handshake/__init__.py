"""
TLS handshake package.
Provides client and server handshake functionality.
"""

from .client import (
    send_client_hello,
    send_client_handshake_messages,
    send_client_change_cipher_spec,
    ClientHelloError,
    KeyExchangeError,
    ChangeCipherSpecError
)

from .server import (
    send_server_hello,
    send_server_change_cipher_spec
)

__all__ = [
    # Client handshake
    'send_client_hello',
    'send_client_handshake_messages', 
    'send_client_change_cipher_spec',

    # Server handshake
    'send_server_hello',
    'send_server_change_cipher_spec',

    # Errors
    'ClientHelloError',
    'KeyExchangeError',
    'ChangeCipherSpecError'
]