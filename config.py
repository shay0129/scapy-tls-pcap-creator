# config.py
class Config:
    SERVER_IP = '10.0.0.1'
    CLIENT1_IP = '192.168.1.1'
    CLIENT2_IP = '192.168.1.2'
    
    GET_REQUEST = b"GET /resource HTTP/1.1\r\nCatch The Flag\r\n\r\n"
    OK_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello, world!"
    BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nBad Request"
    
    OUTPUT_PCAP = "output.pcap"
    SSL_KEYLOG_FILE = "sslkeylog_ctf.log"