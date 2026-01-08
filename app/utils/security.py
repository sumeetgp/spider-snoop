import socket
import ipaddress
from urllib.parse import urlparse

class SecurityUtils:
    @staticmethod
    def is_safe_url(url: str) -> bool:
        """
        Validates that a URL does not point to a private/internal IP address.
        Prevents SSRF attacks.
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
                
            # Resolve hostname to IP
            try:
                ip_list = socket.getaddrinfo(hostname, None)
            except socket.gaierror:
                return False # DNS failure -> unsafe/invalid
                
            for item in ip_list:
                # item is (family, type, proto, canonname, sockaddr)
                # sockaddr is (address, port) for IPv4/v6
                ip_str = item[4][0]
                ip = ipaddress.ip_address(ip_str)
                
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return False
                    
            if parsed.scheme not in ('http', 'https'):
                return False
                
            return True
            
        except Exception:
            return False
