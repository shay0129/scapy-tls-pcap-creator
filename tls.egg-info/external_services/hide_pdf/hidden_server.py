import socket
import sys

def start_hidden_service(exe_path: str, port: int = 1337):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"Hidden service listening on port {port}")
    
    while True:
        client, addr = server.accept()
        try:
            # Get secret phrase
            data = client.recv(1024).decode()
            if data.strip() == "EXPECTED_SECRET_PHRASE":
                # Send CA.exe
                with open(exe_path, 'rb') as f:
                    client.sendall(f.read())
                print(f"CA.exe sent to {addr}")
            else:
                client.sendall(b"Invalid secret phrase")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()

if __name__ == "__main__":
    start_hidden_service("ca.exe")