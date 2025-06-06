"""
TLS utility functions package.
Provides cryptographic, logging, certificate and packet handling utilities.
"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportReturnType=false, reportUnusedVariable=false

from .crypto import (
    generate_session_id,
    compare_to_original,
    compute_mac,
    encrypt_tls12_record_cbc,
    encrypt_finished_message
)

from .logging import (
    setup_logging,
    log_ssl_key,
    print_message_content
)

from .cert import (
    load_cert,
    load_private_key,
    load_server_cert_keys,
    load_certificate_chain,
    verify_key_pair
)

from typing import Callable, List

GetKeyForPacketType = Callable[[List[bytes], int], bytes]
GetMacKeyForPacketType = Callable[[List[bytes], int], bytes]

from .packet import (
    encode_length,
    flags_to_int,
    int_to_bytes_length,
    get_key_for_packet,
    get_mac_key_for_packet
)

# Instead, if needed, use dynamic imports:
def get_verification_functions():
    from ..verification import verify_master_secret
    return verify_master_secret

__all__ = [
    # Crypto utils
    'generate_session_id',
    'compare_to_original',
    'compute_mac',
    'encrypt_tls12_record_cbc',
    'encrypt_finished_message',
    
    # Logging utils
    'setup_logging',
    'log_ssl_key',
    'print_message_content',
    
    # Certificate utils
    'load_cert',
    'load_private_key',
    'load_server_cert_keys',
    'load_certificate_chain',
    
    # Packet utils
    'encode_length',
    'flags_to_int',
    'int_to_bytes_length',
    'get_key_for_packet',
    'get_mac_key_for_packet',
    
    # Verification utils
    'verify_key_pair'
]