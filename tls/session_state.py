from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SessionState:
    """State information for TLS session"""
    seq_num: int = 0
    client_seq_num: int = 0
    server_seq_num: int = 0
    master_secret: Optional[bytes] = None
    handshake_completed: bool = False
    handshake_messages: list = field(default_factory=list)