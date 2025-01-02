"""
TLS certificate handling package.
Provides certificate chain and verification functionality.
"""

from .chain import setup_certificates, handle_master_secret
from .verify import (
    verify_server_public_key,
    verify_server_name,
    verify_certificate_chain,
    get_certificate_names
)

__all__ = [
    'setup_certificates',
    'handle_master_secret',
    'verify_server_public_key',
    'verify_server_name',
    'verify_certificate_chain',
    'get_certificate_names',
]