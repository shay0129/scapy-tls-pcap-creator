"""
Packet utilities module.
Provides functions for handling packet-related operations in TLS/TCP communication.
"""
from typing import List, Optional
from enum import IntFlag
import logging

from ..constants import GeneralConfig

class PacketError(Exception):
    """Base exception for packet operations"""
    pass

class TCPFlags(IntFlag):
    """TCP flags with their corresponding bit values"""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20



def encode_length(length: int, num_bytes: int) -> bytes:
    """
    Encode an integer length value into bytes.
    
    Args:
        length: Integer length to encode
        num_bytes: Number of bytes to use for encoding
        
    Returns:
        bytes: Encoded length
        
    Raises:
        PacketError: If length cannot be encoded in specified bytes
    """
    try:
        if num_bytes <= 0 or num_bytes > GeneralConfig.MAX_PACKET_SIZE:
            raise ValueError(f"Number of bytes must be between 1 and {GeneralConfig.MAX_PACKET_SIZE}")
            
        max_value = (1 << (8 * num_bytes)) - 1
        if length < 0 or length > max_value:
            raise ValueError(
                f"Length {length} cannot be encoded in {num_bytes} bytes "
                f"(max value: {max_value})"
            )
            
        return length.to_bytes(num_bytes, byteorder='big')
        
    except Exception as e:
        raise PacketError(f"Failed to encode length: {e}")

def flags_to_int(flags: str) -> int:
    """
    Convert TCP flag string to integer value.
    
    Args:
        flags: String containing flag characters (e.g., 'PA' for PSH+ACK)
        
    Returns:
        int: Combined flag bits
        
    Raises:
        PacketError: If flags string contains invalid flags
    """
    try:
        result = 0
        flags = flags.upper()
        
        # Validate flags
        valid_flags = set('FSRPAU')
        invalid_flags = set(flags) - valid_flags
        if invalid_flags:
            raise ValueError(f"Invalid TCP flags: {', '.join(invalid_flags)}")
            
        # Map flags to values
        if 'F' in flags:
            result |= TCPFlags.FIN # 0x01
        if 'S' in flags:
            result |= TCPFlags.SYN # 0x02
        if 'R' in flags:
            result |= TCPFlags.RST # 0x04
        if 'P' in flags:
            result |= TCPFlags.PSH # 0x08
        if 'A' in flags:
            result |= TCPFlags.ACK # 0x10
        if 'U' in flags:
            result |= TCPFlags.URG # 0x20
            
        return result
        
    except Exception as e:
        raise PacketError(f"Failed to convert flags to int: {e}")

def flags_to_str(flags: int) -> str:
    """
    Convert TCP flags integer to string representation.
    
    Args:
        flags: Integer containing TCP flags
        
    Returns:
        str: String representation of flags (e.g., 'PA' for PSH+ACK)
    """
    result = []
    if flags & TCPFlags.FIN:
        result.append('F')
    if flags & TCPFlags.SYN:
        result.append('S')
    if flags & TCPFlags.RST:
        result.append('R')
    if flags & TCPFlags.PSH:
        result.append('P')
    if flags & TCPFlags.ACK:
        result.append('A')
    if flags & TCPFlags.URG:
        result.append('U')
    return ''.join(result)

def int_to_bytes_length(n: int) -> int:
    """
    Calculate minimum number of bytes needed to represent an integer.
    
    Args:
        n: Integer to analyze
        
    Returns:
        int: Number of bytes needed
        
    Raises:
        PacketError: If input is invalid
    """
    try:
        if n < 0:
            raise ValueError("Number must be non-negative")
            
        return (n.bit_length() + 7) // 8
        
    except Exception as e:
        raise PacketError(f"Failed to calculate bytes length: {e}")

def get_key_for_packet(
    packet_keys: List[bytes],
    packet_index: int,
    default_key: Optional[bytes] = None
) -> bytes:
    """
    Get encryption key for specified packet index.
    
    Args:
        packet_keys: List of encryption keys
        packet_index: Index of packet
        default_key: Optional default key if index not found
        
    Returns:
        bytes: Encryption key
        
    Raises:
        PacketError: If key cannot be found and no default provided
    """
    try:
        if not packet_keys:
            raise ValueError("Empty packet keys list")
            
        if packet_index < 0:
            raise ValueError("Packet index must be non-negative")
            
        if packet_index >= GeneralConfig.MAX_PACKET_SIZE:
            raise ValueError(f"Packet index exceeds maximum value of {GeneralConfig.MAX_PACKET_SIZE}")
            
        if 0 <= packet_index < len(packet_keys):
            key = packet_keys[packet_index]
            logging.debug(f"Retrieved key for packet {packet_index}")
            return key
            
        if default_key is not None:
            logging.warning(
                f"Using default key for packet {packet_index} "
                f"(index out of range 0-{len(packet_keys)-1})"
            )
            return default_key
            
        raise ValueError(
            f"No key found for packet index {packet_index} "
            f"and no default key provided"
        )
        
    except Exception as e:
        raise PacketError(f"Failed to get key for packet: {e}")

def get_mac_key_for_packet(
    packet_mac_keys: List[bytes],
    packet_index: int,
    default_key: Optional[bytes] = None
) -> bytes:
    """
    Get MAC key for specified packet index in CBC mode.
    
    Args:
        packet_mac_keys: List of MAC keys
        packet_index: Index of packet
        default_key: Optional default key if index not found
        
    Returns:
        bytes: MAC key
        
    Raises:
        PacketError: If key cannot be found and no default provided
    """
    try:
        if not packet_mac_keys:
            raise ValueError("Empty MAC keys list")
            
        if packet_index < 0:
            raise ValueError("Packet index must be non-negative")
            
        if packet_index >= GeneralConfig.MAX_PACKET_SIZE:
            raise ValueError(f"Packet index exceeds maximum value of {GeneralConfig.MAX_PACKET_SIZE}")
            
        if 0 <= packet_index < len(packet_mac_keys):
            key = packet_mac_keys[packet_index]
            logging.debug(f"Retrieved MAC key for packet {packet_index}")
            return key
            
        if default_key is not None:
            logging.warning(
                f"Using default MAC key for packet {packet_index} "
                f"(index out of range 0-{len(packet_mac_keys)-1})"
            )
            return default_key
            
        raise ValueError(
            f"No MAC key found for packet index {packet_index} "
            f"and no default key provided"
        )
        
    except Exception as e:
        raise PacketError(f"Failed to get MAC key for packet: {e}")
    

def int_to_bytes_length(n: int) -> int:
    """
    Calculate byte length needed for integer.
    
    Args:
        n: Integer to analyze
        
    Returns:
        int: Number of bytes needed
    """
    return (n.bit_length() + 7) // 8

def get_key_for_packet(packet_keys: list, packet_index: int) -> bytes:
    """
    Get encryption key for specific packet.
    
    Args:
        packet_keys: List of keys
        packet_index: Packet index
        
    Returns:
        bytes: Key for specified packet
        
    Raises:
        ValueError: If key not found
    """
    if 0 <= packet_index < len(packet_keys):
        return packet_keys[packet_index]
    raise ValueError(f"No key found for packet index {packet_index}")

def get_mac_key_for_packet(packet_mac_keys: list, packet_index: int) -> bytes:
    """
    Get MAC key for CBC mode packet.
    
    Args:
        packet_mac_keys: List of MAC keys
        packet_index: Packet index
        
    Returns:
        bytes: MAC key for specified packet
        
    Raises:
        ValueError: If key not found
    """
    if 0 <= packet_index < len(packet_mac_keys):
        return packet_mac_keys[packet_index]
    raise ValueError(f"No MAC key found for packet index {packet_index}")

def int_to_bytes_length(n: int) -> int:
    """
    Calculate byte length needed for integer.
    
    Args:
        n: Integer to analyze
        
    Returns:
        int: Number of bytes needed
    """
    return (n.bit_length() + 7) // 8

def get_key_for_packet(packet_keys: list, packet_index: int) -> bytes:
    """
    Get encryption key for specific packet.
    
    Args:
        packet_keys: List of keys
        packet_index: Packet index
        
    Returns:
        bytes: Key for specified packet
        
    Raises:
        PacketError: If key not found
    """
    if 0 <= packet_index < len(packet_keys):
        return packet_keys[packet_index]
    raise PacketError(f"No key found for packet index {packet_index}")
