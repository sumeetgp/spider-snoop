
import socket
import sys
import ssl
import time

def simulate_icap_upload(host, port, auth_token, use_ssl=True):
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Setup Connection (SSL or Plain)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # For testing self-signed/staging
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
            
        sock.connect((host, port))
        print(f"Connected to {host}:{port} (SSL: {use_ssl})")
        
        # Test Payload (e.g. a small text file with secrets)
        payload = b"Confirming Cloud ICAP Upload. SSN: 000-00-1234"
        payload_len = len(payload)
        
        # Construct HTTP Header (fake body part)
        http_header = (
            "PUT /cloud_upload.txt HTTP/1.1\r\n"
            "Host: example.com\r\n"
            f"Content-Length: {payload_len}\r\n"
            "\r\n"
        )
        http_header_len = len(http_header)
        
        # Construct ICAP REQMOD Header
        icap_request = (
            f"REQMOD icap://{host}:{port}/reqmod ICAP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Authorization: Bearer {auth_token}\r\n"
            f"Encapsulated: req-hdr=0, req-body={http_header_len}\r\n"
            "\r\n"
        )
        
        # Send Headers
        sock.sendall(icap_request.encode() + http_header.encode())
        
        # Send Chunked Body
        chunk_header = f"{payload_len:x}\r\n".encode()
        sock.sendall(chunk_header + payload + b"\r\n")
        
        # End Chunk
        sock.sendall(b"0\r\n\r\n")
        
        # Read Response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
                
        print("\n--- ICAP Response ---")
        print(response.decode(errors='replace'))
        
        if b"ICAP/1.0 200 OK" in response and b"HTTP/1.1 403 Forbidden" in response:
            print("\nSUCCESS: Sensitive data blocked!")
            return True
        elif b"ICAP/1.0 204 No Modifications Needed" in response:
            print("\nSUCCESS: Scan completed (No block triggered)")
            return True
        else:
            print("\nFAILED: Unexpected response")
            return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_icap_file.py <auth_token> [host] [port] [ssl]")
        sys.exit(1)
        
    token = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "icap.spidercob.com"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
    use_ssl = sys.argv[4].lower() == "true" if len(sys.argv) > 4 else True
    
    simulate_icap_upload(host, port, token, use_ssl)
