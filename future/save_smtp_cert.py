import socket
import ssl
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def save_certificate(host, port, localhostname):
    with socket.create_connection((host, port)) as s:
        s.settimeout(10)  # Set a generous timeout to handle slow server responses

        # Helper function to send commands properly with CR+LF
        def send_command(command):
            s.sendall(command.encode() + b'\r\n')
            time.sleep(1)  # Give the server a second to respond
            return s.recv(4096)  # Read a larger buffer to ensure full server response

        # Initial connection and reading the greeting
        greeting = s.recv(4096)
        print("Greeting response:", greeting.decode())

        # Sending EHLO with proper line endings and reading response
        ehlo_response = send_command(f"EHLO {localhostname}")
        print("EHLO response:", ehlo_response.decode())

        # Start TLS and reading response
        starttls_response = send_command("STARTTLS")
        print("STARTTLS response:", starttls_response.decode())

        # Check if server is ready for TLS
        if b'220' not in starttls_response:
            print("Server not ready for TLS")
            return None

        # Wrap the socket with SSL
        context = ssl.create_default_context()
        ssl_socket = context.wrap_socket(s, server_hostname=host)

        # Get the certificate in DER format
        certificate_der = ssl_socket.getpeercert(binary_form=True)

        # Save the certificate in PEM format
        certificate_pem = ssl.DER_cert_to_PEM_cert(certificate_der)
        filename = f"{host}_smtp.cer"
        with open(filename, 'w') as file:
            file.write(certificate_pem)

        # Load certificate using cryptography to extract SAN details
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        ip_addresses = san.value.get_values_for_type(x509.IPAddress)

        # Cleanup
        ssl_socket.close()

        # Return filename and SAN details
        return filename, dns_names, ip_addresses


# Example usage
host = 'det-nsw-edu-au.mail.protection.outlook.com'
port = 25
localhostname = socket.gethostname()
filename, dns_names, ip_addresses = save_certificate(host, port, localhostname)
print(f"Certificate saved to {filename}")
print("DNS Names in SAN:", dns_names)
print("IP Addresses in SAN:", ip_addresses)
