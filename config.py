class Config:
    SERVER_IP = '10.0.0.1'
    CLIENT1_IP = '192.168.1.1'
    CLIENT2_IP = '192.168.1.2'
    
    # Fixing the GET request to a valid HTTP format
    GET_REQUEST = (
        b"GET /resource HTTP/1.1\r\n"
        b"Host: server.local\r\n"
        b"User-Agent: Custom-Client/1.0\r\n" # client's type
        b"Connection: close\r\n"
        b"\r\n"
    )
    
    # Valid content-length same as the length of the content
    OK_RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 12\r\n"
        b"\r\n"
        b"Hello, world!"  # exactly 12 bytes
    )
    
    BAD_REQUEST = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"Bad Request"  # Exactly 11 bytes
    )
    
    OUTPUT_PCAP = "../api/output.pcap"
    SSL_KEYLOG_FILE = "../api/sslkeylog_ctf.log"