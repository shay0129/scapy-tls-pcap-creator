"""
Logging utilities module.
Configures and manages logging for TLS session simulation.
"""
from typing import Optional, Union
from datetime import datetime
from pathlib import Path
import logging.handlers
import sys

from ..constants import LoggingConfig

class LoggingError(Exception):
    """Base exception for logging operations"""
    pass

def setup_logging(
    log_path: Optional[Union[str, Path]] = None,
    level: Optional[int] = None,  # Make level optional
    format_str: str = LoggingConfig.FORMAT,
    console: bool = True,
    rotate: bool = True
) -> None:
    """
    Configure logging settings with both file and console output.
    
    Args:
        log_path: Path to log file (optional)
        level: Logging level (optional, defaults to LoggingConfig.LEVEL)
        format_str: Log message format
        console: Whether to output to console
        rotate: Whether to use rotating file handler
        
    Raises:
        LoggingError: If logging setup fails
    """
    try:
        # Use LoggingConfig.LEVEL if no level is provided
        if level is None:
            level = LoggingConfig.LEVEL
            
        # Reset any existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Create formatter
        formatter = logging.Formatter(format_str)
        handlers = []

        # Add file handler if path provided
        if log_path:
            log_path = Path(log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            if rotate:
                file_handler = logging.handlers.RotatingFileHandler(
                    log_path,
                    maxBytes=LoggingConfig.MAX_SIZE,
                    backupCount=LoggingConfig.BACKUP_COUNT,
                    mode='a'
                )
            else:
                file_handler = logging.FileHandler(log_path, mode='a')

            file_handler.setFormatter(formatter)
            handlers.append(file_handler)

        # Add console handler if requested
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            handlers.append(console_handler)

        # Configure root logger
        logging.basicConfig(
            level=level,
            handlers=handlers,
            force=True
        )

        logging.info("Logging configured successfully")
        log_config_info(log_path if log_path else "console only")

    except Exception as e:
        raise LoggingError(f"Failed to setup logging: {e}")
def log_config_info(log_path: Union[str, Path]) -> None:
    """Log configuration information"""
    logging.info("=== Logging Configuration ===")
    logging.info(f"Log file: {log_path}")
    logging.info(f"Log level: {logging.getLogger().getEffectiveLevel()}")
    logging.info(f"Timestamp: {datetime.now().isoformat()}")
    logging.info("==========================")

def log_ssl_key(client_random: str, master_secret: str, keylog_path: Optional[Union[str, Path]] = None) -> None:
    """
    Log SSL key to NSS key log file format.
    
    Args:
        client_random: Client random value in hex
        master_secret: Master secret in hex
        keylog_path: Path to key log file (optional)
        
    Raises:
        LoggingError: If key logging fails
    """
    try:
        if not keylog_path:
            keylog_path = Path("../documents/SSLKEYLOG.LOG")

        keylog_path = Path(keylog_path)
        keylog_path.parent.mkdir(parents=True, exist_ok=True)

        # Validate hex strings
        try:
            int(client_random, 16)
            int(master_secret, 16)
        except ValueError:
            raise LoggingError("Client random and master secret must be hex strings")

        # Create key log entry
        key_entry = f"CLIENT_RANDOM {client_random} {master_secret}\n"

        # Append to key log file
        with keylog_path.open("a") as f:
            f.write(key_entry)

        logging.info(f"SSL key logged to {keylog_path}")
        logging.debug(f"Key entry: {key_entry.strip()}")

    except Exception as e:
        raise LoggingError(f"Failed to log SSL key: {e}")

def print_message_content(
    message: bytes,
    max_lines: int = LoggingConfig.MAX_LINES_DISPLAY,
    max_binary: int = LoggingConfig.MAX_BINARY_DISPLAY
) -> None:
    """
    Print message content with smart handling of text/binary data.
    
    Args:
        message: Message content to print
        max_lines: Maximum number of text lines to display
        max_binary: Maximum number of bytes to display for binary data
    """
    if not message:
        logging.info("Empty message")
        return

    try:
        # Try to decode as UTF-8
        decoded = message.decode('utf-8')
        lines = decoded.split('\n')
        
        # Log first max_lines
        for line in lines[:max_lines]:
            line = line.strip()
            if line:  # Skip empty lines
                logging.info(f"Content: {line}")
                
        # Indicate if there are more lines
        if len(lines) > max_lines:
            logging.info(f"... {len(lines) - max_lines} more lines ...")

    except UnicodeDecodeError:
        # Handle binary data
        hex_data = message[:max_binary].hex()
        formatted_hex = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
        logging.info(f"Binary data: {formatted_hex}")
        
        if len(message) > max_binary:
            logging.info(f"... {len(message) - max_binary} more bytes ...")

def get_logger(name: str, level: int = LoggingConfig.LEVEL) -> logging.Logger: 
    """ 
    Get a configured logger instance. 
     
    Args: 
        name: Logger name 
        level: Logging level 
         
    Returns: 
        logging.Logger: Configured logger instance 
    """ 
    logger = logging.getLogger(name) 
    logger.setLevel(level) 
    return logger

def print_message_content(message: bytes) -> None:
    """
    Print message content with binary data handling.
    
    Args:
        message: Message to print
    """
    try:
        decoded = message.decode('utf-8')
        lines = decoded.split('\n')
        for line in lines[:10]:
            logging.info(line)
        if len(lines) > 10:
            logging.info("...")
    except UnicodeDecodeError:
        logging.info(f"Binary data (first 100 bytes): {message[:100].hex()}")
        if len(message) > 100:
            logging.info("...")