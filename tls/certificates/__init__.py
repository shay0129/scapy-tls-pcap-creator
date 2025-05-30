# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportReturnType=false, reportUnusedVariable=false
"""
TLS certificate handling package.
Provides certificate chain and verification functionality.
"""

from .chain import setup_certificates as _setup_certificates
from ..session_state import SessionState
from .verify import (
    verify_server_public_key,
    verify_server_name,
    verify_certificate_chain,
    get_certificate_names
)
from ..crypto.keys import handle_master_secret

def setup_certificates(session: SessionState) -> None:
    return _setup_certificates(session)

__all__ = [
    'setup_certificates',
    'handle_master_secret',
    'verify_server_public_key',
    'verify_server_name',
    'verify_certificate_chain',
    'get_certificate_names',
]